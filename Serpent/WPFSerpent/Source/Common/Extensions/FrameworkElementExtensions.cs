using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;

namespace WPFSerpent.Source.Common.Extensions
{
    public static class FrameworkElementExtensions
    {
        private static readonly object _animateSync = new object();
        private static readonly Dictionary<FrameworkElement, Storyboard> StoryBoards = new Dictionary<FrameworkElement, Storyboard>();

        public static Task AnimateAsync(this FrameworkElement fwElement, PropertyPath propertyPath, AnimationTimeline animation)
        {
            lock (_animateSync)
            {
                var tcs = new TaskCompletionSource<bool>();
                var storyBoard = new Storyboard();
                void storyBoard_Completed(object s, EventArgs e) => tcs.TrySetResult(true);

                StoryBoards.TryGetValue(fwElement, out var sb);
                var isSbInDict = sb != null;
                if (isSbInDict)
                {
                    StoryBoards[fwElement].Stop(fwElement);
                    StoryBoards.Remove(fwElement);
                    StoryBoards.Add(fwElement, storyBoard);
                }

                Storyboard.SetTarget(animation, fwElement);
                Storyboard.SetTargetProperty(animation, propertyPath);
                storyBoard.Children.Add(animation);
                storyBoard.Completed += storyBoard_Completed;

                storyBoard.Begin(fwElement, true);
                return tcs.Task;
            }
        }

        public static Task AnimateAsync(this FrameworkElement fwElement, DependencyProperty dp, AnimationTimeline animation)
        {
            return AnimateAsync(fwElement, new PropertyPath(dp), animation);
        }

        public static Task AnimateAsync(this FrameworkElement fwElement, string propertyPath, AnimationTimeline animation)
        {
            return AnimateAsync(fwElement, new PropertyPath(propertyPath), animation);
        }

        public static int ZIndex(this FrameworkElement fe)
        {
            return Panel.GetZIndex(fe);
        }

        public static void ZIndex(this FrameworkElement fe, int zINdex)
        {
            Panel.SetZIndex(fe, zINdex);
        }
    }
}
