using System.Windows;
using WPFSerpent.Source.Common.Utils.UtilsClasses;

namespace WPFSerpent.Source.Common.Extensions
{
    public static class WindowExtensions
    {
        public static Point WindowPointToScreen(this Window wnd, Point p)
        {
            var screenMousePos = wnd.PointToScreen(p);
            var screen = wnd.Screen().DeviceBounds;
            var screenWidth = screen.Width;
            var screenHeight = screen.Height;
            var screenDPIWidth = SystemParameters.FullPrimaryScreenWidth;
            var screenDPIHeight = SystemParameters.FullPrimaryScreenHeight;

            return new Point(
                screenDPIWidth / (screenWidth / screenMousePos.X),
                screenDPIHeight / (screenHeight / screenMousePos.Y));
        }

        public static WPFScreen Screen(this Window wnd)
        {
            return WPFScreen.GetScreenFrom(wnd);
        }
    }
}