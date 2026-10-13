#include <stddef.h>
#include <stdbool.h>
void wgNativeTrayCreate(const void *bytes, size_t count);
void wgNativeTraySetIcon(const void *bytes, size_t count);
void wgNativeTraySetMenu(const char *json);
void wgNativeTraySetTooltip(const char *text);
void wgNativeTraySetConnected(bool connected);
void wgNativeTrayDestroy(void);
