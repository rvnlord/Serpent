using System.Collections.Generic;

namespace WpfSerpent.Source.Common.Extensions.Collections
{
    public static class StackExtensions
    {
        public static T NextToTop<T>(this Stack<T> s)
        {
            var top = s.Pop();
            var nextToTop = s.Peek();
            s.Push(top);

            return nextToTop;
        }
    }
}
