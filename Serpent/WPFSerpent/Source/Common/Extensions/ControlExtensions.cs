using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace WPFSerpent.Source.Common.Extensions
{
    public static class ControlExtensions
    {
        private static async void AnimateChangeColor(this FrameworkElement control, Color color)
        {
            var colorAni = new ColorAnimation(color, new Duration(TimeSpan.FromMilliseconds(500)));
            await control.AnimateAsync("(Panel.Background).(SolidColorBrush.Color)", colorAni);
        }

        public static void Highlight(this FrameworkElement control, Color color)
        {
            control.AnimateChangeColor(color);
        }
    }
}