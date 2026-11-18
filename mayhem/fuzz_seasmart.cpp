// Fuzzes the Seasmart ($PCDIN) text codec: SeasmartToN2k on arbitrary text, and N2kToSeasmart on
// whatever message that produced, into exactly-sized and too-small heap buffers.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "N2kMsg.h"
#include "Seasmart.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;

  char *text = new char[size + 1];
  memcpy(text, data, size);
  text[size] = '\0';

  tN2kMsg msg;
  uint32_t timestamp = 0;
  if (SeasmartToN2k(text, timestamp, msg)) {
    size_t need = 30 + 2 * (size_t)msg.DataLen;
    size_t sizes[3] = {need, need - 1, 0};
    for (int i = 0; i < 3; i++) {
      char *out = new char[sizes[i] ? sizes[i] : 1];
      N2kToSeasmart(msg, timestamp, out, sizes[i]);
      delete[] out;
    }
  }

  delete[] text;
  return 0;
}
