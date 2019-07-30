using System.Collections.Generic;

namespace WPFSerpent.Source.Common.Extensions.Collections
{
    public static class IEnumerableExtensions
    {
        public static string JoinAsString<T>(this IEnumerable<T> enumerable, string strBetween = "")
        {
            return string.Join(strBetween, enumerable);
        }

        public static List<object> DisableControls(this IEnumerable<object> controls)
        {
            var disabledControls = new List<object>();
            foreach (var c in controls)
            {
                var piIsEnabled = c.GetType().GetProperty("IsEnabled");
                var isEnabled = (bool?)piIsEnabled?.GetValue(c);
                if (isEnabled == true)
                {
                    piIsEnabled.SetValue(c, false);
                    disabledControls.Add(c);
                }
            }
            return disabledControls;
        }

        public static void EnableControls(this IEnumerable<object> controls)
        {
            foreach (var c in controls)
            {
                var piIsEnabled = c.GetType().GetProperty("IsEnabled");
                piIsEnabled?.SetValue(c, true);
            }
        }
    }
}
