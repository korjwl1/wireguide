#include "../connection_icon_linux.h"
#include <string.h>

static gchar *icon_name(const char *path) {
    gchar *name = g_path_get_basename(path);
    if (g_str_has_suffix(name, ".png")) name[strlen(name)-4] = '\0';
    return name;
}

static GdkTexture *window_icon(GtkWidget *window, const char *name) {
    if (g_strcmp0(gtk_window_get_icon_name(GTK_WINDOW(window)), name) != 0) return NULL;
    GtkIconTheme *theme = gtk_icon_theme_get_for_display(gtk_widget_get_display(window));
    GtkIconPaintable *icon = gtk_icon_theme_lookup_icon(theme, name, NULL, 256, 1,
                                                       GTK_TEXT_DIR_NONE, GTK_ICON_LOOKUP_FORCE_REGULAR);
    if (icon == NULL) return NULL;
    GFile *file = gtk_icon_paintable_get_file(icon);
    GdkTexture *texture = file == NULL ? NULL : gdk_texture_new_from_file(file, NULL);
    g_object_unref(icon);
    return texture;
}

int main(int argc, char **argv) {
    if (argc != 3 || !gtk_init_check()) return 2;
    gchar *directory = g_path_get_dirname(argv[1]);
    gchar *base = icon_name(argv[1]), *connected = icon_name(argv[2]);
    GFile *original_file = g_file_new_for_path(argv[1]);
    GdkTexture *original = gdk_texture_new_from_file(original_file, NULL);
    g_object_unref(original_file);
    if (original == NULL || gdk_texture_get_width(original) != 256 || gdk_texture_get_height(original) != 256) return 3;
    const gsize stride = 256*4, count = 256*stride;
    guchar *original_pixels = g_malloc(count), *pixels = g_malloc(count);
    gdk_texture_download(original, original_pixels, stride);
    GtkWidget *window = gtk_window_new();
    g_object_ref_sink(window);
    for (int i = 0; i < 25; i++) {
        if (!wgSetWindowConnectionIcon(window, directory, connected)) return 4;
        GdkTexture *icon = window_icon(window, connected);
        if (icon == NULL || gdk_texture_get_width(icon) != 256 || gdk_texture_get_height(icon) != 256) return 5;
        gdk_texture_download(icon, pixels, stride);
        g_object_unref(icon);
        const guchar *pixel = pixels + 212*stride + 44*4;
        // gdk_texture_download uses native-endian premultiplied ARGB32.
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
        const guchar expected[] = {89, 199, 52, 255};
#else
        const guchar expected[] = {255, 52, 199, 89};
#endif
        if (memcmp(pixel, expected, sizeof(expected)) != 0) {
            g_printerr("Unexpected badge pixel at (44, 212): %u,%u,%u,%u\n", pixel[0], pixel[1], pixel[2], pixel[3]);
            return 6;
        }
        if (!wgSetWindowConnectionIcon(window, directory, base)) return 7;
        icon = window_icon(window, base);
        if (icon == NULL || gdk_texture_get_width(icon) != 256 || gdk_texture_get_height(icon) != 256) return 8;
        gdk_texture_download(icon, pixels, stride);
        g_object_unref(icon);
        if (memcmp(pixels, original_pixels, count) != 0) return 9;
    }
    gtk_window_destroy(GTK_WINDOW(window));
    g_object_unref(window);
    g_object_unref(original);
    g_free(original_pixels);
    g_free(pixels);
    g_free(directory);
    g_free(base);
    g_free(connected);
    g_print("PASS: GTK4 themed icons, green pixels and exact base restoration across 25 On/Off cycles\n");
    return 0;
}
