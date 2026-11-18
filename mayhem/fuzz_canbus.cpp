// Fuzzes the NMEA2000 stack end to end: raw CAN frames go in through a fake CAN driver, so the
// frame reassembly (fast packet, ISO TP), address claim, group-function, system-message and
// device-list code all run. Each input builds and tears down its own bus; time is a fake clock.
//
// Input: [mode][config][time step][records...], a record being [id:4 LE][len:1][len%9 data bytes].
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "N2kDeviceList.h"
#include "N2kGroupFunctionDefaultHandlers.h"
#include "N2kMsg.h"
#include "N2kStream.h"
#include "NMEA2000.h"
#include "fake_clock.h"

namespace {

class NullStream : public N2kStream {
public:
  int read() { return -1; }
  int peek() { return -1; }
  size_t write(const uint8_t *, size_t n) { return n; }
};

class FakeBus : public tNMEA2000 {
public:
  FakeBus(const uint8_t *frames, size_t size)
      : frames_(frames), size_(size), pos_(0) {
    SetN2kCANMsgBufSize(8);
    // Open() would allocate N2kCANMsgBuf and register six heap-allocated default group
    // function handlers that tNMEA2000 never frees. Do the same here but keep ownership.
    N2kCANMsgBuf = new tN2kCANMsg[MaxN2kCANMsgs];
    for (int i = 0; i < MaxN2kCANMsgs; i++) N2kCANMsgBuf[i].FreeMessage();
    h60928_ = new tN2kGroupFunctionHandlerForPGN60928(this);
    h126464_ = new tN2kGroupFunctionHandlerForPGN126464(this);
    h126993_ = new tN2kGroupFunctionHandlerForPGN126993(this);
    h126996_ = new tN2kGroupFunctionHandlerForPGN126996(this);
    h126998_ = new tN2kGroupFunctionHandlerForPGN126998(this);
    hdef_ = new tN2kGroupFunctionHandler(this, 0);
    AddGroupFunctionHandler(h60928_);
    AddGroupFunctionHandler(h126464_);
    AddGroupFunctionHandler(h126993_);
    AddGroupFunctionHandler(h126996_);
    AddGroupFunctionHandler(h126998_);
    AddGroupFunctionHandler(hdef_);
  }

  ~FakeBus() {
    if (Devices != 0) {
      for (int i = 0; i < DeviceCount; i++) {
        delete Devices[i].LocalProductInformation;
        delete[] Devices[i].PGNSequenceCounters;
      }
      delete[] Devices;
    }
    delete[] N2kCANMsgBuf;
    delete[] CANSendFrameBuf;
    delete h60928_;
    delete h126464_;
    delete h126993_;
    delete h126996_;
    delete h126998_;
    delete hdef_;
    if (LocalConfigurationInformationData != 0) {
      free(LocalConfigurationInformationData);
      LocalConfigurationInformationData = 0;
    }
  }

  bool FramesLeft() const { return pos_ + 5 <= size_; }

protected:
  bool CANSendFrame(unsigned long, unsigned char, const unsigned char *, bool) { return true; }
  bool CANOpen() { return true; }
  bool CANGetFrame(unsigned long &id, unsigned char &len, unsigned char *buf) {
    if (pos_ + 5 > size_) return false;
    id = (unsigned long)(frames_[pos_] | (frames_[pos_ + 1] << 8) | (frames_[pos_ + 2] << 16) |
                         ((unsigned long)frames_[pos_ + 3] << 24)) & 0x1FFFFFFFUL;
    len = frames_[pos_ + 4] % 9;
    pos_ += 5;
    size_t n = size_ - pos_ < len ? size_ - pos_ : len;
    memset(buf, 0, 8);
    memcpy(buf, frames_ + pos_, n);
    len = (unsigned char)n;
    pos_ += n;
    return true;
  }

private:
  const uint8_t *frames_;
  size_t size_;
  size_t pos_;
  tN2kGroupFunctionHandlerForPGN60928 *h60928_;
  tN2kGroupFunctionHandlerForPGN126464 *h126464_;
  tN2kGroupFunctionHandlerForPGN126993 *h126993_;
  tN2kGroupFunctionHandlerForPGN126996 *h126996_;
  tN2kGroupFunctionHandlerForPGN126998 *h126998_;
  tN2kGroupFunctionHandler *hdef_;
};

class DeviceList : public tN2kDeviceList {
public:
  explicit DeviceList(tNMEA2000 *n2k) : tN2kDeviceList(n2k) {}
  ~DeviceList() {
    for (int i = 0; i < N2kMaxBusDevices; i++) {
      delete Sources[i];
      Sources[i] = 0;
    }
  }
};

enum { kMaxKept = 4 };
tN2kMsg g_kept[kMaxKept];
int g_nkept;

void OnMsg(const tN2kMsg &msg) {
  if (g_nkept < kMaxKept) g_kept[g_nkept++] = msg;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 3) return -1;

  static const tNMEA2000::tN2kMode modes[] = {
      tNMEA2000::N2km_ListenOnly, tNMEA2000::N2km_NodeOnly, tNMEA2000::N2km_ListenAndNode,
      tNMEA2000::N2km_SendOnly, tNMEA2000::N2km_ListenAndSend};
  const tNMEA2000::tN2kMode mode = modes[data[0] % 5];
  const uint8_t config = data[1];
  const uint32_t step = 1 + 40 * (uint32_t)data[2];

  g_fake_now_ms = 1000;
  g_nkept = 0;
  NullStream fwd;

  FakeBus n2k(data + 3, size - 3);
  DeviceList list(&n2k);
  n2k.SetDeviceCount(1 + (config & 1));
  n2k.SetMode(mode, 20 + (config >> 4));
  n2k.SetForwardStream(&fwd);
  n2k.SetForwardType((config & 2) ? tNMEA2000::fwdt_Text : tNMEA2000::fwdt_Actisense);
  n2k.SetForwardOwnMessages((config & 4) != 0);
  n2k.SetMsgHandler(OnMsg);
  n2k.EnableForward((config & 8) != 0);

  // Open needs the 200 ms CAN-ready delay and address claim needs ~250 ms to pass.
  for (int i = 0; i < 4; i++) {
    g_fake_now_ms += 300;
    n2k.ParseMessages();
  }
  int guard = 0;
  while (n2k.FramesLeft() && guard++ < 4096) {
    g_fake_now_ms += step;
    n2k.ParseMessages();
    list.ReadResetIsListUpdated();
  }
  for (int i = 0; i < g_nkept; i++) {
    n2k.SendMsg(g_kept[i]);
    g_fake_now_ms += step;
    n2k.ParseMessages();
  }
  for (int s = 0; s < 256; s += 17) {
    const tNMEA2000::tDevice *d = list.FindDeviceBySource((uint8_t)s);
    if (d != 0) {
      d->GetName();
      d->GetSource();
    }
  }
  return 0;
}
