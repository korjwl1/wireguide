#include <gtk/gtk.h>

static int wgSetWindowConnectionIcon(void *window, const void *bytes, size_t count) {
    if (window == NULL || bytes == NULL || count == 0) return 0;
    GdkPixbufLoader *loader = gdk_pixbuf_loader_new();
    gboolean ok = gdk_pixbuf_loader_write(loader, bytes, count, NULL);
    gboolean closed = gdk_pixbuf_loader_close(loader, NULL);
    ok = ok && closed;
    if (ok) {
        GdkPixbuf *image = gdk_pixbuf_loader_get_pixbuf(loader);
        if (image != NULL) gtk_window_set_icon(GTK_WINDOW(window), image);
        else ok = FALSE;
    }
    g_object_unref(loader);
    return ok;
}
