using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;

// Ogólne informacje o zestawie są kontrolowane poprzez następujący 
// zbiór atrybutów. Zmień wartości tych atrybutów by zmodyfikować informacje
// powiązane z zestawem.
[assembly: AssemblyTitle("WpfApplication1")]
[assembly: AssemblyDescription("")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("Acer")]
[assembly: AssemblyProduct("WpfApplication1")]
[assembly: AssemblyCopyright("Copyright © Acer 2015")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]
[assembly: DisableDpiAwareness]

// Ustawienie wartości ComVisible na false sprawia, że typy w tym zestawie nie będą widoczne 
// dla składników COM.  Jeśli potrzebny jest dostęp do typu w tym zestawie z 
// COM, ustaw wartość ComVisible na true, dla danego typu.
[assembly: ComVisible(false)]

//Aby rozpocząć kompilację lokalizowalnych aplikacji, ustaw 
//<UICulture>CultureYouAreCodingWith</UICulture> w pliku .csproj
//wewnątrz <PropertyGroup>.  Na przykład, jeśli używany jest język angielski USA
//ustaw w plikach źródłowych wartość <UICulture> na en-US.  Następnie usuń komentarz dla
//poniższego atrybutu NeutralResourceLanguage.  Zaktualizuj wartość "en-US" w
//poniższej linii tak, aby dopasować ustawienia UICulture w pliku projektu.

//[assembly: NeutralResourcesLanguage("en-US", UltimateResourceFallbackLocation.Satellite)]


[assembly: ThemeInfo(
    ResourceDictionaryLocation.None, //gdzie znajdują się słowniki zasobów specyficznych dla motywu
    //(używane, jeśli nie można odnaleźć zasobu na stronie, 
    // lub słowniki zasobów aplikacji)
    ResourceDictionaryLocation.SourceAssembly //gdzie znajduje się ogólny słownik zasobów
    //(używane, jeśli nie można odnaleźć zasobu na stronie, 
    // aplikacji lub słowników zasobów specyficznych dla motywu)
)]


// Informacje o wersji zestawu zawierają następujące cztery wartości:
//
//      Wersja główna
//      Wersja pomocnicza 
//      Numer kompilacji
//      Rewizja
//
// Można określać wszystkie wartości lub używać domyślnych numerów kompilacji i poprawki 
// poprzez użycie '*', jak pokazane jest poniżej:
// [assembly: AssemblyVersion("1.0.*")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
