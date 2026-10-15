#include "../connection_icon_linux.h"
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 3 || !gtk_init_check(&argc, &argv)) return 2;
    gchar *base = NULL, *connected = NULL;
    gsize base_len = 0, connected_len = 0;
    if (!g_file_get_contents(argv[1], &base, &base_len, NULL) || !g_file_get_contents(argv[2], &connected, &connected_len, NULL)) return 3;
    GdkPixbuf *original = gdk_pixbuf_new_from_file(argv[1], NULL);
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    g_object_ref_sink(window);
    for (int i = 0; i < 25; i++) {
        if (!wgSetWindowConnectionIcon(window, connected, connected_len)) return 4;
        GdkPixbuf *icon = gtk_window_get_icon(GTK_WINDOW(window));
        if (icon == NULL || gdk_pixbuf_get_width(icon) != 256) return 5;
        const guchar *pixel = gdk_pixbuf_read_pixels(icon) + 211*gdk_pixbuf_get_rowstride(icon) + 211*gdk_pixbuf_get_n_channels(icon);
        if (pixel[0] != 52 || pixel[1] != 199 || pixel[2] != 89) return 6;
        if (!wgSetWindowConnectionIcon(window, base, base_len)) return 7;
        icon = gtk_window_get_icon(GTK_WINDOW(window));
        if (icon == NULL || original == NULL || gdk_pixbuf_get_byte_length(icon) != gdk_pixbuf_get_byte_length(original) || memcmp(gdk_pixbuf_read_pixels(icon), gdk_pixbuf_read_pixels(original), gdk_pixbuf_get_byte_length(original)) != 0) return 8;
    }
    gtk_widget_destroy(window);
    g_object_unref(window);
    g_object_unref(original);
    g_free(base);
    g_free(connected);
    g_print("PASS: native GTK green pixels and exact base restoration across 25 On/Off cycles\n");
    return 0;
}
