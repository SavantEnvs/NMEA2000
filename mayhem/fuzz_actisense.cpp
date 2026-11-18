// Fuzzes tActisenseReader: bytes from an Actisense serial stream -> tN2kMsg, then the message is
// printed and converted to Seasmart the way the library's own consumers do.
#include <new>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include "ActisenseReader.h"
#include "N2kMsg.h"
#include "N2kStream.h"
#include "Seasmart.h"

namespace {

class MemStream : public N2kStream {
public:
  MemStream(const uint8_t *d, size_t n) : data_(d), size_(n), pos_(0) {}
  int read() { return pos_ < size_ ? data_[pos_++] : -1; }
  int peek() { return pos_ < size_ ? data_[pos_] : -1; }
  size_t write(const uint8_t *, size_t n) { return n; }

private:
  const uint8_t *data_;
  size_t size_;
  size_t pos_;
};

MemStream *g_sink;

void OnMsg(const tN2kMsg &msg) {
  msg.Print(g_sink);
  msg.Print(g_sink, true);
  char buf[30 + 2 * tN2kMsg::MaxDataLen];
  N2kToSeasmart(msg, msg.MsgTime, buf, sizeof(buf));
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;

  MemStream sink(nullptr, 0);
  g_sink = &sink;

  // tActisenseReader leaves MsgBuf uninitialised; zero it so a run depends on the input alone.
  alignas(tActisenseReader) static unsigned char storage[sizeof(tActisenseReader)];
  memset(storage, 0, sizeof(storage));
  tActisenseReader *reader = new (storage) tActisenseReader();

  MemStream in(data + 1, size - 1);
  reader->SetReadStream(&in);
  reader->SetDefaultSource(data[0]);
  reader->SetMsgHandler(OnMsg);
  reader->ParseMessages();
  (void)reader->Handling();

  reader->~tActisenseReader();
  return 0;
}
