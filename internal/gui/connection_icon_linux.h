#include <gtk/gtk.h>

static int wgSetWindowConnectionIcon(void *window, const char *directory, const char *name) {
    if (window == NULL || directory == NULL || name == NULL) return 0;
    GtkIconTheme *theme = gtk_icon_theme_get_for_display(gtk_widget_get_display(GTK_WIDGET(window)));
    if (theme == NULL) return 0;
    const char *previous = g_object_get_data(G_OBJECT(theme), "wireguide-icon-directory");
    if (g_strcmp0(previous, directory) != 0) {
        gtk_icon_theme_add_search_path(theme, directory);
        g_object_set_data_full(G_OBJECT(theme), "wireguide-icon-directory", g_strdup(directory), g_free);
    }
    if (!gtk_icon_theme_has_icon(theme, name)) return 0;
    gtk_window_set_icon_name(GTK_WINDOW(window), name);
    return 1;
}
