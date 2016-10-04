using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Microsoft.Win32;
using System.Reflection;
using System.IO;
using System.ComponentModel;
using System.Diagnostics;

namespace WpfDemo
{
    public partial class MainWindow : Window
    {
        public static readonly string ProgramVersion = "(v1.46c - 18-05-2015)";
        Stopwatch sw = new Stopwatch();

        SerpentCipher serpent = new SerpentCipher(); // inicjalizuję obiekt klasy szyfrującej
        BackgroundWorker bgwEncrypt = new BackgroundWorker(); // inicjalizuję klasy obsługujące szyfreowanie asynchronicznie
        BackgroundWorker bgwDecrypt = new BackgroundWorker();
        BackgroundWorker bgwBreakEncryption = new BackgroundWorker();

        bool KeyChanged { get; set; } // deklaruję właściwości
        bool RoundsChanged { get; set; }

        double CurrWidth { get; set; }
        double CurrHeight { get; set; }

        public MainWindow()
        {
            InitializeComponent();
            this.Loaded += MainWindow_Loaded; // dodaję event handler, który będzie wyzwalany przy załadowaniu interfejsu użytkownika
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            serpent.AlphabetLength = 256; // uzupełniam zmienne klasy szyfrującej
            serpent.EncryptionProgressChanged += new EncryptionProgressChangedEventHandler(MainWindow_EncryptionProgressChanged);
            pbStatus.Visibility = Visibility.Collapsed;
            txtbStatus.Visibility = Visibility.Collapsed;
            lblOperation.Visibility = Visibility.Collapsed;

            bgwEncrypt.WorkerReportsProgress = true; // dodaję event handlery do klas działających asynchronicznie
            bgwEncrypt.DoWork += bgwEncrypt_DoWork;
            bgwEncrypt.ProgressChanged += bgwEncryptDecrypt_ProgressChanged;
            bgwEncrypt.RunWorkerCompleted += bgwEncrypt_RunWorkerCompleted;

            bgwDecrypt.WorkerReportsProgress = true;
            bgwDecrypt.DoWork += bgwDecrypt_DoWork;
            bgwDecrypt.ProgressChanged += bgwEncryptDecrypt_ProgressChanged;
            bgwDecrypt.RunWorkerCompleted += bgwDecrypt_RunWorkerCompleted;

            KeyChanged = RoundsChanged = false; // inicjalizuję właściwości

            foreach (FrameworkElement c in gMain.Children) // bezpośrednia pętla przez typ Control weźmie także textblock, wyrzuci błąd, nauluje dalsze operacje funkcji i NIE pokaże błędu użytkownikowi, dlatego pętla jest po tym typie.
            {
                if (c is Control)
                {
                    c.HorizontalAlignment = HorizontalAlignment.Left;
                    c.VerticalAlignment = VerticalAlignment.Top;
                }
            }

            double smallMargin = 5.0;
            double bigMargin = 10.0;

            try
            {
                pbStatus.Margin = new Thickness(txtSourceFile.Margin.Left, txtSourceFile.Margin.Top, 0, 0);
                txtbStatus.Margin = new Thickness(txtSourceFile.Margin.Left + pbStatus.Width, txtSourceFile.Margin.Top + ((pbStatus.Height - txtbStatus.Height) / 2.0), 0, 0);
                lblOperation.Visibility = Visibility.Visible; // inaczej ActualHeight zwróci 0, bo label Visibility jest Collapsed
                lblOperation.Margin = new Thickness(txtSourceFile.Margin.Left + bigMargin - smallMargin, txtSourceFile.Margin.Top + ((pbStatus.Height - lblOperation.ActualHeight) / 2.0), 0, 0);
                lblOperation.Visibility = Visibility.Collapsed;
                btnChooseSourceFile.Margin = new Thickness(txtSourceFile.Margin.Left + txtSourceFile.ActualWidth + smallMargin, txtSourceFile.Margin.Top, 0, 0);
                btnGenerateKey.Margin = new Thickness(txtSourceFile.Margin.Left + txtSourceFile.ActualWidth + smallMargin, txtSourceFile.ActualHeight + smallMargin + btnEncrypt.ActualHeight + smallMargin + lblKey.ActualHeight + smallMargin, 0, 0);

                btnEncrypt.Margin = new Thickness(txtSourceFile.Margin.Left, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin, 0, 0);
                btnDecrypt.Margin = new Thickness(txtSourceFile.Margin.Left + btnEncrypt.ActualWidth + smallMargin, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin, 0, 0);
                btnClear.Margin = new Thickness(txtSourceFile.Margin.Left + btnEncrypt.ActualWidth + smallMargin + btnDecrypt.ActualWidth + smallMargin, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin, 0, 0);

                lblKey.Margin = new Thickness(txtSourceFile.Margin.Left, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin + btnEncrypt.ActualHeight + smallMargin, 0, 0);
                txtKey.Margin = new Thickness(txtSourceFile.Margin.Left, txtSourceFile.ActualHeight + smallMargin + btnEncrypt.ActualHeight + smallMargin + lblKey.ActualHeight + smallMargin, 0, 0);

                lblMode.Margin = new Thickness(txtSourceFile.Margin.Left, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin + btnEncrypt.ActualHeight + smallMargin + lblKey.ActualHeight + smallMargin + txtKey.ActualHeight + smallMargin + lblMode.ActualHeight + smallMargin, 0, 0);
                rbStandardMode.Margin = new Thickness(txtSourceFile.Margin.Left + bigMargin, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin + btnEncrypt.ActualHeight + smallMargin + lblKey.ActualHeight + smallMargin + txtKey.ActualHeight + smallMargin + lblMode.ActualHeight + smallMargin + lblMode.ActualHeight + smallMargin, 0, 0);
                rbBitSliceMode.Margin = new Thickness(txtSourceFile.Margin.Left + bigMargin, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin + btnEncrypt.ActualHeight + smallMargin + lblKey.ActualHeight + smallMargin + txtKey.ActualHeight + smallMargin + lblMode.ActualHeight + smallMargin + rbStandardMode.ActualHeight + lblMode.ActualHeight + smallMargin, 0, 0);

                cbUnlockResize.Margin = new Thickness(txtSourceFile.Margin.Left, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin + btnEncrypt.ActualHeight + smallMargin + lblKey.ActualHeight + smallMargin + txtKey.ActualHeight + smallMargin + lblMode.ActualHeight + smallMargin + rbStandardMode.ActualHeight + smallMargin + rbBitSliceMode.ActualHeight + smallMargin + lblMode.ActualHeight + smallMargin, 0, 0);

                lblEncrMode.Margin = new Thickness((txtSourceFile.ActualWidth + smallMargin + btnGenerateKey.ActualWidth) / 3.5, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin + btnEncrypt.ActualHeight + smallMargin + lblKey.ActualHeight + smallMargin + txtKey.ActualHeight + smallMargin + lblKeyMode.ActualHeight + smallMargin, 0, 0);
                rbECBEncrMode.Margin = new Thickness((txtSourceFile.ActualWidth + smallMargin + btnGenerateKey.ActualWidth) / 3.5 + bigMargin, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin + btnEncrypt.ActualHeight + smallMargin + lblKey.ActualHeight + smallMargin + txtKey.ActualHeight + smallMargin + lblEncrMode.ActualHeight + smallMargin + lblEncrMode.ActualHeight + smallMargin, 0, 0);
                rbCBCEncrMode.Margin = new Thickness((txtSourceFile.ActualWidth + smallMargin + btnGenerateKey.ActualWidth) / 3.5 + bigMargin, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin + btnEncrypt.ActualHeight + smallMargin + lblKey.ActualHeight + smallMargin + txtKey.ActualHeight + smallMargin + lblEncrMode.ActualHeight + smallMargin + lblEncrMode.ActualHeight + smallMargin + rbECBEncrMode.ActualHeight, 0, 0);

                lblKeyMode.Margin = new Thickness((txtSourceFile.ActualWidth + smallMargin + btnGenerateKey.ActualWidth) * 2 / 3.5, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin + btnEncrypt.ActualHeight + smallMargin + lblKey.ActualHeight + smallMargin + txtKey.ActualHeight + smallMargin + lblKeyMode.ActualHeight + smallMargin, 0, 0);
                rbKeyBytes.Margin = new Thickness((txtSourceFile.ActualWidth + smallMargin + btnGenerateKey.ActualWidth) * 2 / 3.5 + bigMargin, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin + btnEncrypt.ActualHeight + smallMargin + lblKey.ActualHeight + smallMargin + txtKey.ActualHeight + smallMargin + lblKeyMode.ActualHeight + smallMargin + lblKeyMode.ActualHeight + smallMargin, 0, 0);
                rbKeyChars.Margin = new Thickness((txtSourceFile.ActualWidth + smallMargin + btnGenerateKey.ActualWidth) * 2 / 3.5 + bigMargin, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin + btnEncrypt.ActualHeight + smallMargin + lblKey.ActualHeight + smallMargin + txtKey.ActualHeight + smallMargin + lblKeyMode.ActualHeight + smallMargin + rbKeyBytes.ActualHeight + lblKeyMode.ActualHeight + smallMargin, 0, 0);

                //lblBitSliceDoesNotWork.Margin = new Thickness(rbBitSliceMode.Margin.Left + rbBitSliceMode.ActualWidth + smallMargin, rbBitSliceMode.Margin.Top, 0, 0);

                this.SizeToContent = SizeToContent.WidthAndHeight;
                CurrWidth = this.ActualWidth;
                CurrHeight = this.ActualHeight;
                this.SizeToContent = SizeToContent.Manual;

                this.Width = CurrWidth;
                this.Height = CurrHeight;

                // elementy pozycjonowane względem prawego marginesu

                txtRounds.Margin = new Thickness(gMain.ActualWidth - txtRounds.ActualWidth, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin, 0, 0);
                lblRounds.Margin = new Thickness(gMain.ActualWidth - txtRounds.ActualWidth - smallMargin - lblRounds.ActualWidth, txtSourceFile.Margin.Top + txtSourceFile.ActualHeight + smallMargin + ((txtRounds.ActualHeight - lblRounds.ActualHeight) / 2.0), 0, 0);

                lblSign.Margin = new Thickness(gMain.ActualWidth - lblSign.ActualWidth - 2.0, gMain.ActualHeight - lblSign.ActualHeight, 0, 0);
            }
            catch (Exception ex)
            {
                MessageBox.Show(string.Format("Wystąpił problem. Elementy okna nie zostały poprawnie wczytane (Wyjątek: {0}).", ex.Message));
            }

            rbKeyBytes.IsChecked = true;
            rbECBEncrMode.IsChecked = true;

            rbKeyChars.Checked += rbKeyChars_Checked;
            rbKeyBytes.Checked += rbKeyBytes_Checked;
            txtKey.TextChanged += txtKey_TextChanged;
            txtSourceFile.TextChanged += txtSourceFile_TextChanged;
            txtRounds.TextChanged += txtRounds_TextChanged;
            rbBitSliceMode.Checked += rbBitSliceMode_Checked;
            rbStandardMode.Checked += rbStandardMode_Checked;

            rbBitSliceMode.IsChecked = true;

            lblKeyValidation.Content = string.Empty;

            Brush red = new SolidColorBrush(Color.FromArgb(0xFF, 0xE0, 0x51, 0x51));
            //lblBitSliceDoesNotWork.Foreground = red;
            //lblBitSliceDoesNotWork.Visibility = Visibility.Collapsed;

            this.Title += " " + ProgramVersion;
        }

        private void btnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            Validation vd = new Validation();
            List<object> validationResults = new List<object>();
            Mode algMode = rbStandardMode.IsChecked == true ? Mode.Standard : Mode.BitSlice;
            EncryptionMode encrMode = rbECBEncrMode.IsChecked == true ? EncryptionMode.ECB : EncryptionMode.CBC;
            KeyMode keyMode = rbKeyBytes.IsChecked == true ? KeyMode.Bytes : KeyMode.Chars;

            if (vd.ValidateForm(this, ActionType.Encryption, out validationResults))
            {
                byte[] key = (byte[])validationResults[0];
                int rounds = (int)validationResults[1];
                lblOperation.Content = "Trwa Szyfrowanie...";

                ModifyGuiEventHandlers(OperationStatus.Start);
                ModifyGuiVisibility(OperationStatus.Start, sender);

                sw.Start();
                bgwEncrypt.RunWorkerAsync(new object[] { key, txtSourceFile.Text, rounds, algMode, encrMode }); // wywołuję operację szyfrowania asynchronicznie względem interfejsu użytkownika (dzięki czemu pozostaje on responsywny), przekazując zmienne do drugiego wątku w postaci tablicy obiektów.
            }
        }

        private void bgwEncrypt_DoWork(object sender, DoWorkEventArgs e)
        {
            SerpentCipher serpent = new SerpentCipher(); 
            serpent.AlphabetLength = 256;
            serpent.EncryptionProgressChanged += new EncryptionProgressChangedEventHandler(MainWindow_EncryptionProgressChanged); 
            byte[] key = (byte[])((object[])e.Argument)[0]; 
            string sourceFile = ((object[])e.Argument)[1].ToString();
            int rounds = (int)((object[])e.Argument)[2];
            Mode algMode = (Mode)((object[])e.Argument)[3];
            EncryptionMode encrMode = (EncryptionMode)((object[])e.Argument)[4];
            bool flag = serpent.Encrypt(sourceFile, key, rounds, algMode, encrMode); 
            e.Result = flag;
        }

        private void bgwEncrypt_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            sw.Stop();
            UpdateGuiOnCompletion(string.Format("Plik został poprawnie zaszyfrowany (Czas: {0}). ", sw.Elapsed), sender, e, ActionType.Encryption); // przekazuję wiadomość i wynik operacji szyfrowania do metody aktualizującej interfejs użytkownika.
            sw.Reset();
        }

        private void btnDecrypt_Click(object sender, RoutedEventArgs e)
        {
            Validation vd = new Validation();
            List<object> validationResults = new List<object>();
            Mode algMode = rbStandardMode.IsChecked == true ? Mode.Standard : Mode.BitSlice;
            EncryptionMode encrMode = rbECBEncrMode.IsChecked == true ? EncryptionMode.ECB : EncryptionMode.CBC;
            KeyMode keyMode = rbKeyBytes.IsChecked == true ? KeyMode.Bytes : KeyMode.Chars;

            if (vd.ValidateForm(this, ActionType.Decryption, out validationResults))
            {
                byte[] key = (byte[])validationResults[0];
                int rounds = (int)validationResults[1];

                lblOperation.Content = "Trwa Deszyfrowanie...";

                ModifyGuiEventHandlers(OperationStatus.Start);
                ModifyGuiVisibility(OperationStatus.Start, sender);

                sw.Start();
                bgwDecrypt.RunWorkerAsync(new object[] { key, txtSourceFile.Text, rounds, algMode, encrMode }); // wywołuję operację szyfrowania asynchronicznie względem interfejsu użytkownika (dzięki czemu pozostaje on responsywny), przekazując zmienne do drugiego wątku w postaci tablicy obiektów.
            }
        }

        private void bgwDecrypt_DoWork(object sender, DoWorkEventArgs e)
        {
            SerpentCipher serpent = new SerpentCipher(); // tworzę instancję klasy szyfrującej w drugim wątku programu
            serpent.AlphabetLength = 256; // inicjalizuję długość alfabetu
            serpent.EncryptionProgressChanged += new EncryptionProgressChangedEventHandler(MainWindow_EncryptionProgressChanged); // dodaję własny event handler obsłgująct pasek stanu operacji
            byte[] key = (byte[])((object[])e.Argument)[0];
            string sourceFile = ((object[])e.Argument)[1].ToString();
            int rounds = (int)((object[])e.Argument)[2];
            Mode algMode = (Mode)((object[])e.Argument)[3];
            EncryptionMode encrMode = (EncryptionMode)((object[])e.Argument)[4];
            bool flag = serpent.Decrypt(sourceFile, key, rounds, algMode, encrMode); 
            e.Result = flag; // przekazuję informację czy deszyfrowanie się powiodło do zdarzenia, które jest wykonywane następnie.
        }

        private void bgwDecrypt_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            sw.Stop();
            UpdateGuiOnCompletion(string.Format("Plik został poprawnie odszyfrowany. (Czas: {0}). ", sw.Elapsed), sender, e, ActionType.Decryption); // przekazuję wiadomość i wynik operacji deszyfrowania do metody aktualizującej interfejs użytkownika.
            sw.Reset();
        }

        private void UpdateGuiOnCompletion(string Message, object sender, RunWorkerCompletedEventArgs e, ActionType Operation)
        {
            bool opResult = (bool)e.Result; 

            if (opResult)
                MessageBox.Show(Message, "Sukces", MessageBoxButton.OK, MessageBoxImage.Information);

            ModifyGuiVisibility(OperationStatus.End, sender);
            ModifyGuiEventHandlers(OperationStatus.End);
        }

        private void MainWindow_EncryptionProgressChanged(object sender, EncryptionProgressChangedEventArgs e) // zdarzenie wywoływane jest przy każdej iteracji metody szyfrującej, dla każdej części pliku
        {
            if (e.ActionType == ActionType.Encryption) // przekazuję postęp operacji szyfrującej lub deszyfrującej do domyślnego zdarzenia wywoływanego przez drugi wątek przy aktualizacji postępu
                bgwEncrypt.ReportProgress(e.Progress); // jednocześnie wywołując to zdarzenie
            else if (e.ActionType == ActionType.Decryption)
                bgwDecrypt.ReportProgress(e.Progress);
        }

        private void bgwEncryptDecrypt_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            pbStatus.Value = e.ProgressPercentage; // aktualizuję pasek postępu operacji

            if (e.ProgressPercentage > 33)
                lblOperation.Foreground = Brushes.Black;
            else
                lblOperation.Foreground = Brushes.White;
        }

        private void btnClear_Click(object sender, RoutedEventArgs e)
        {
            txtKey.Text = "klucz...";
            txtKey.GotFocus += txtKey_GotFocus;
            KeyChanged = false;
            txtKey.FontStyle = FontStyles.Italic;

            if (rbBitSliceMode.IsChecked == false)
                txtRounds.Text = "rundy...";

            txtRounds.GotFocus += txtRounds_GotFocus;
            RoundsChanged = false;
            txtRounds.FontStyle = FontStyles.Italic;

            txtSourceFile.Text = "Wybierz lub przeciągnij plik...";
        }

        private void txtKey_GotFocus(object sender, RoutedEventArgs e)
        {
            string extension = System.IO.Path.GetExtension(txtSourceFile.Text); // pobieram rozszerzenie, że ścieżki pliku
            MessageBoxResult result = MessageBoxResult.None;

            if (string.IsNullOrEmpty(txtKey.Text) || txtKey.Text == "klucz...")
            {
                FormatTextBoxOnFocus((TextBox)sender);
                ((TextBox)sender).GotFocus -= txtKey_GotFocus;
                KeyChanged = true;
            }
            else
            {
                result = MessageBox.Show("Czy na pewno chcesz wyczyścić klucz?. ", "Ostrzeżenie", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    FormatTextBoxOnFocus((TextBox)sender);
                    ((TextBox)sender).GotFocus -= txtKey_GotFocus;
                    KeyChanged = true;
                }
                else if (result == MessageBoxResult.No)
                {
                    ((TextBox)sender).FontStyle = FontStyles.Normal;
                    ((TextBox)sender).GotFocus -= txtKey_GotFocus;
                    KeyChanged = true;
                }
                else if (result == MessageBoxResult.Cancel)
                    txtSourceFile.Focus();
            }
        }

        private void txtRounds_GotFocus(object sender, RoutedEventArgs e)
        {
            if (((TextBox)sender).IsReadOnly == false)
            {
                FormatTextBoxOnFocus((TextBox)sender);
                ((TextBox)sender).GotFocus -= txtRounds_GotFocus;
                RoundsChanged = true;
            }
        }

        private void FormatTextBoxOnFocus(TextBox txtB)
        {
            txtB.Text = string.Empty;
            txtB.FontWeight = FontWeights.Normal;
            txtB.FontStyle = FontStyles.Normal;
        }

        private void btnChooseSourceFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();

            dlg.DefaultExt = ".txt";
            dlg.InitialDirectory = @"C:\";

            Nullable<bool> result = dlg.ShowDialog();

            if (result.HasValue && result.Value)
            {
                txtSourceFile.Text = dlg.FileName;
                string extension = System.IO.Path.GetExtension(txtSourceFile.Text); // pobieram rozszerzenie, że ścieżki pliku

                if (extension != ".serpent") // aktualizuję pole rozszerzenia pliku
                {
                    byte[] key = serpent.RandomizeKey(); // wywołuję metodę losującą klucze, jeżli użytkownik dodał plik. 
                    UpdateGuiWithRandomizedKeys(key);
                }
            }
        }

        private void txtSourceFile_Drop(object sender, DragEventArgs e) // obsługa operacji drag and drop
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) // ustawiam wartość ścieżki jako ścieżkę przeciągniętego pliku
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                txtSourceFile.Text = files[0];

                string extension = System.IO.Path.GetExtension(txtSourceFile.Text); // pobieram rozszerzenie, że ścieżki pliku

                if (extension != ".serpent") // aktualizuję pole rozszerzenia pliku
                {
                    byte[] key = serpent.RandomizeKey(); // wywołuję metodę losującą klucze, jeżli użytkownik przeciągnał plik. 
                    UpdateGuiWithRandomizedKeys(key);
                }
            }
        }

        private void UpdateGuiWithRandomizedKeys(byte[] key)
        {
            Validation vd = new Validation();

            if (vd.CheckIfKeyIsEmpty(this)) // jeśli klucz jest pusty
                txtKey.Text = vd.GetKeyString(key, rbKeyBytes.IsChecked == true ? KeyMode.Bytes : KeyMode.Chars);

            if (vd.CheckIfRoundsNumIsEmpty(this))
                txtRounds.Text = "32";
        }

        private void txtSourceFile_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) // ustawiam zmienne efektów dla drag and dropa
                e.Effects = DragDropEffects.All;
            else
                e.Effects = DragDropEffects.None;
        }

        private void txtSourceFile_PreviewDragOver(object sender, DragEventArgs e)
        {
            e.Handled = true; // linijka wymagana, żeby drag and drop działał
        }

        private void txtSourceFile_TextChanged(object sender, TextChangedEventArgs e)
        {
            PerformTextChangedValidation();
        }

        private void txtRounds_TextChanged(object sender, TextChangedEventArgs e)
        {
            PerformTextChangedValidation();
        }

        private void txtKey_TextChanged(object sender, TextChangedEventArgs e)
        {
            PerformTextChangedValidation();
        }

        private void rbKeyChars_Checked(object sender, RoutedEventArgs e)
        {
            string extension = System.IO.Path.GetExtension(txtSourceFile.Text); 

            if (extension != ".serpent")
            {
                txtKey.Text = string.Empty;
                byte[] key = serpent.RandomizeKey();
                UpdateGuiWithRandomizedKeys(key);
            }
            else
            {
                if (!string.IsNullOrEmpty(txtKey.Text))
                {
                    MessageBoxResult result = MessageBox.Show("Obecny klucz zostanie usunięty, czy na pewno chcesz kontynuować? ", "Błąd", MessageBoxButton.YesNo, MessageBoxImage.Warning);

                    if (result == MessageBoxResult.Yes)
                        txtKey.Text = string.Empty;
                    else
                    {
                        rbKeyBytes.Checked -= rbKeyBytes_Checked;
                        rbKeyBytes.IsChecked = true;
                        rbKeyBytes.Checked += rbKeyBytes_Checked;
                    }
                }
            }

            PerformTextChangedValidation();
        }

        private void rbKeyBytes_Checked(object sender, RoutedEventArgs e)
        {
            string extension = System.IO.Path.GetExtension(txtSourceFile.Text);

            if (extension != ".serpent")
            {
                txtKey.Text = string.Empty;
                byte[] key = serpent.RandomizeKey();
                UpdateGuiWithRandomizedKeys(key);
            }
            else
            {
                if (!string.IsNullOrEmpty(txtKey.Text))
                {
                    MessageBoxResult result = MessageBox.Show("Obecny klucz zostanie usunięty, czy na pewno chcesz kontynuować?. ", "Błąd", MessageBoxButton.YesNo, MessageBoxImage.Warning);

                    if (result == MessageBoxResult.Yes)
                        txtKey.Text = string.Empty;
                    else
                    {
                        rbKeyChars.Checked -= rbKeyChars_Checked;
                        rbKeyChars.IsChecked = true;
                        rbKeyChars.Checked += rbKeyChars_Checked;
                    }
                }
            }

            PerformTextChangedValidation();
        }

        private void rbStandardMode_Checked(object sender, RoutedEventArgs e)
        {
            txtRounds.IsReadOnly = false;
        }

        private void rbBitSliceMode_Checked(object sender, RoutedEventArgs e)
        {
            txtRounds.Text = "32";
            txtRounds.IsReadOnly = true;
        }

        private void PerformTextChangedValidation()
        {
            Validation vd = new Validation();
            List<object> validationResults = new List<object>();
            Brush green = new SolidColorBrush(Color.FromArgb(0xFF, 0x70, 0x8C, 0x00));
            Brush red = new SolidColorBrush(Color.FromArgb(0xFF, 0xE0, 0x51, 0x51));
            UTF8Encoding enc = new UTF8Encoding();

            bool vdResult = vd.ValidateForm(this, ActionType.ChangingText, out validationResults);

            byte[] key = null;
            if (vdResult || (validationResults != null && (byte[])validationResults[0] != null))
            {
                key = (byte[])validationResults[0];

                lblKeyValidation.Foreground = vdResult ? green : red;
                lblKeyValidation.Content = string.Format("Klucz: {0} bit{3} ({1} bajt{4}) ({2})", key.Length * 8, key.Length, vdResult ? "Poprawny" : "Niepoprawny", vd.GetWordEnding(key.Length * 8), vd.GetWordEnding(key.Length));
            }
        }

        private void ModifyGuiVisibility(OperationStatus Status, object sender)
        {
            if (Status == OperationStatus.Start)
            {
                lblOperation.Visibility = Visibility.Visible;

                foreach (FrameworkElement item in ((Panel)(sender as Button).Parent).Children) // wyłączam pola formularza podczas operacji szyfrowania
                    if (item is Button)
                        item.IsEnabled = false;
                    else if (item is TextBox)
                        (item as TextBox).IsReadOnly = true;
                    else if (item is RadioButton)
                        (item as RadioButton).IsEnabled = false;

                pbStatus.Visibility = Visibility.Visible;
                txtbStatus.Visibility = Visibility.Visible;
                txtSourceFile.Visibility = Visibility.Collapsed;
                btnChooseSourceFile.Visibility = Visibility.Collapsed;

                lblMode.Opacity = 0.4;
                lblKeyMode.Opacity = 0.4;
                lblEncrMode.Opacity = 0.4;
            }
            else if (Status == OperationStatus.End)
            {
                lblOperation.Visibility = Visibility.Collapsed;
                lblOperation.Foreground = Brushes.White;

                pbStatus.Visibility = Visibility.Collapsed;
                txtbStatus.Visibility = Visibility.Collapsed;
                pbStatus.Value = 0;

                foreach (FrameworkElement item in ((Panel)btnEncrypt.Parent).Children) // aktualizuję widoczność paneli
                    if (item is Button)
                        item.IsEnabled = true;
                    else if (item is TextBox)
                    {
                        if ((item as TextBox) == txtRounds && rbBitSliceMode.IsChecked == true)
                            (item as TextBox).IsReadOnly = true;
                        else
                            (item as TextBox).IsReadOnly = false;
                    }
                    else if (item is RadioButton)
                        (item as RadioButton).IsEnabled = true;

                txtSourceFile.IsReadOnly = true;
                txtSourceFile.Visibility = Visibility.Visible;
                btnChooseSourceFile.Visibility = Visibility.Visible;

                lblMode.Opacity = 1.0;
                lblKeyMode.Opacity = 1.0;
                lblEncrMode.Opacity = 1.0;
            }
        }

        private void ModifyGuiEventHandlers(OperationStatus Status)
        {
            if (Status == OperationStatus.Start)
            {
                if (!KeyChanged) // usuwam event handlery czyszczące pola formularza, jeżeli użytkownik przeciągając plik wygenerował je automatycznie
                    txtKey.GotFocus -= txtKey_GotFocus;
                if (!RoundsChanged)
                    txtRounds.GotFocus -= txtRounds_GotFocus;
            }
            else if (Status == OperationStatus.End)
            {
                if (!KeyChanged) // dodaję z powrotem event handlery, jeżeli pola formularza zostały przed operacją wygenerowane automatycznie poprzez przeciągnięcie pliku
                    txtKey.GotFocus += txtKey_GotFocus;
                if (!RoundsChanged)
                    txtRounds.GotFocus += txtRounds_GotFocus;
            }
        }

        private void cbUnlockResize_Click(object sender, RoutedEventArgs e)
        {
            if (cbUnlockResize.IsChecked == true)
            {
                this.ResizeMode = ResizeMode.CanResize;
                this.SizeToContent = System.Windows.SizeToContent.WidthAndHeight;
                double tWidth = this.ActualWidth;
                double tHeight = this.ActualHeight;
                this.SizeToContent = System.Windows.SizeToContent.Manual;
                this.Width = tWidth;
                this.Height = tHeight;
            }
            else if (cbUnlockResize.IsChecked == false)
            {
                this.ResizeMode = ResizeMode.CanMinimize;
                this.Width = CurrWidth;
                this.Height = CurrHeight;
            }
        }

        private void btnGenerateKey_Click(object sender, RoutedEventArgs e)
        {
            txtKey.Text = string.Empty;
            byte[] key = serpent.RandomizeKey();
            UpdateGuiWithRandomizedKeys(key);
        }
    }

    public static partial class ExtensionMethods
    {
        public static void PerformClick(this Button btn)
        {
            btn.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        }
    }

    public enum OperationStatus
    {
        Start,
        End
    }
}
