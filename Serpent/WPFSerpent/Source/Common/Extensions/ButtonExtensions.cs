using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;

namespace WPFSerpent.Source.Common.Extensions
{
    public static class ButtonExtensions
    {
        public static void PerformClick(this Button btn)
        {
            btn.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        }
    }
}
