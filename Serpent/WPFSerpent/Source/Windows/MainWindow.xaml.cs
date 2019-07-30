using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Forms;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using WPFSerpent.Source.Common.Extensions;
using WPFSerpent.Source.Models;
using Button = System.Windows.Controls.Button;
using ButtonBase = System.Windows.Controls.Primitives.ButtonBase;
using DataFormats = System.Windows.DataFormats;
using DragDropEffects = System.Windows.DragDropEffects;
using DragEventArgs = System.Windows.DragEventArgs;
using MessageBox = System.Windows.MessageBox;
using MouseEventArgs = System.Windows.Input.MouseEventArgs;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;
using Panel = System.Windows.Controls.Panel;
using RadioButton = System.Windows.Controls.RadioButton;
using TextBox = System.Windows.Controls.TextBox;
using Validation = WPFSerpent.Source.Models.Validation;

namespace WPFSerpent.Source.Windows
{
    public partial class MainWindow
    {
        private NotifyIcon _notifyIcon;

        private readonly Stopwatch sw = new Stopwatch();

        private SerpentCipher serpent = new SerpentCipher(); // inicjalizuję obiekt klasy szyfrującej
        private readonly BackgroundWorker bgwEncrypt = new BackgroundWorker(); // inicjalizuję klasy obsługujące szyfreowanie asynchronicznie
        private readonly BackgroundWorker bgwDecrypt = new BackgroundWorker();

        private bool KeyChanged { get; set; } // deklaruję właściwości
        private bool RoundsChanged { get; set; }

        public MainWindow()
        {
            InitializeComponent();
            Loaded += MainWindow_Loaded; // dodaję event handler, który będzie wyzwalany przy załadowaniu interfejsu użytkownika
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            var iconHandle = Properties.Resources.NotifyIcon.GetHicon();
            var icon = System.Drawing.Icon.FromHandle(iconHandle);

            _notifyIcon = new NotifyIcon
            {
                BalloonTipTitle = lblWindowTitle.Content.ToString(),
                BalloonTipText = @"is hidden here",
                Icon = icon
            };
            _notifyIcon.Click += notifyIcon_Click;

            serpent.AlphabetLength = 256; // uzupełniam zmienne klasy szyfrującej
            serpent.EncryptionProgressChanged += MainWindow_EncryptionProgressChanged;
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
        }

        private void btnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            var vd = new Validation();
            var algMode = rbStandardMode.IsChecked == true ? Mode.Standard : Mode.BitSlice;
            var encrMode = rbECBEncrMode.IsChecked == true ? EncryptionMode.ECB : EncryptionMode.CBC;

            if (vd.ValidateForm(this, ActionType.Encryption, out var validationResults))
            {
                var key = (byte[])validationResults[0];
                var rounds = (int)validationResults[1];
                lblOperation.Content = "Encrypting...";

                ModifyGuiEventHandlers(OperationStatus.Start);
                ModifyGuiVisibility(OperationStatus.Start, sender);

                sw.Start();
                bgwEncrypt.RunWorkerAsync(new object[] { key, txtSourceFile.Text, rounds, algMode, encrMode }); // wywołuję operację szyfrowania asynchronicznie względem interfejsu użytkownika (dzięki czemu pozostaje on responsywny), przekazując zmienne do drugiego wątku w postaci tablicy obiektów.
            }
        }

        private void bgwEncrypt_DoWork(object sender, DoWorkEventArgs e)
        {
            serpent = new SerpentCipher { AlphabetLength = 256 };
            serpent.EncryptionProgressChanged += MainWindow_EncryptionProgressChanged; 
            var key = (byte[])((object[])e.Argument)[0]; 
            var sourceFile = ((object[])e.Argument)[1].ToString();
            var rounds = (int)((object[])e.Argument)[2];
            var algMode = (Mode)((object[])e.Argument)[3];
            var encrMode = (EncryptionMode)((object[])e.Argument)[4];
            var flag = serpent.Encrypt(sourceFile, key, rounds, algMode, encrMode); 
            e.Result = flag;
        }

        private void bgwEncrypt_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            sw.Stop();
            UpdateGuiOnCompletion($"File has been correctly Encrypted (Time: {sw.Elapsed}). ", sender, e, ActionType.Encryption); // przekazuję wiadomość i wynik operacji szyfrowania do metody aktualizującej interfejs użytkownika.
            sw.Reset();
        }

        private void btnDecrypt_Click(object sender, RoutedEventArgs e)
        {
            var vd = new Validation();
            var algMode = rbStandardMode.IsChecked == true ? Mode.Standard : Mode.BitSlice;
            var encrMode = rbECBEncrMode.IsChecked == true ? EncryptionMode.ECB : EncryptionMode.CBC;

            if (vd.ValidateForm(this, ActionType.Decryption, out var validationResults))
            {
                var key = (byte[])validationResults[0];
                var rounds = (int)validationResults[1];

                lblOperation.Content = "Decrypting...";

                ModifyGuiEventHandlers(OperationStatus.Start);
                ModifyGuiVisibility(OperationStatus.Start, sender);

                sw.Start();
                bgwDecrypt.RunWorkerAsync(new object[] { key, txtSourceFile.Text, rounds, algMode, encrMode }); // wywołuję operację szyfrowania asynchronicznie względem interfejsu użytkownika (dzięki czemu pozostaje on responsywny), przekazując zmienne do drugiego wątku w postaci tablicy obiektów.
            }
        }

        private void bgwDecrypt_DoWork(object sender, DoWorkEventArgs e)
        {
            serpent = new SerpentCipher { AlphabetLength = 256  }; // tworzę instancję klasy szyfrującej w drugim wątku programu i inicjalizuję długość alfabetu
            serpent.EncryptionProgressChanged += MainWindow_EncryptionProgressChanged; // dodaję własny event handler obsłgująct pasek stanu operacji
            var key = (byte[])((object[])e.Argument)[0];
            var sourceFile = ((object[])e.Argument)[1].ToString();
            var rounds = (int)((object[])e.Argument)[2];
            var algMode = (Mode)((object[])e.Argument)[3];
            var encrMode = (EncryptionMode)((object[])e.Argument)[4];
            var flag = serpent.Decrypt(sourceFile, key, rounds, algMode, encrMode); 
            e.Result = flag; // przekazuję informację czy deszyfrowanie się powiodło do zdarzenia, które jest wykonywane następnie.
        }

        private void bgwDecrypt_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            sw.Stop();
            UpdateGuiOnCompletion($"FIle has been correctly Decrypted (Time: {sw.Elapsed}). ", sender, e, ActionType.Decryption); // przekazuję wiadomość i wynik operacji deszyfrowania do metody aktualizującej interfejs użytkownika.
            sw.Reset();
        }

        private void UpdateGuiOnCompletion(string Message, object sender, RunWorkerCompletedEventArgs e, ActionType Operation)
        {
            var opResult = (bool)e.Result; 

            if (opResult)
                MessageBox.Show(Message, "Success", MessageBoxButton.OK, MessageBoxImage.Information);

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

            lblOperation.Foreground = e.ProgressPercentage > 33 ? Brushes.Blue : Brushes.White;
            txtbStatus.Foreground = e.ProgressPercentage > 50 ? Brushes.Blue : Brushes.White;
        }

        private void btnClear_Click(object sender, RoutedEventArgs e)
        {
            txtKey.Text = "key...";
            txtKey.GotFocus += txtKey_GotFocus;
            KeyChanged = false;
            txtKey.FontStyle = FontStyles.Italic;

            if (rbBitSliceMode.IsChecked == false)
                txtRounds.Text = "rounds...";

            txtRounds.GotFocus += txtRounds_GotFocus;
            RoundsChanged = false;
            txtRounds.FontStyle = FontStyles.Italic;

            txtSourceFile.Text = "Select or drop a file...";
        }

        private void txtKey_GotFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(txtKey.Text) || txtKey.Text == "key...")
            {
                FormatTextBoxOnFocus((TextBox)sender);
                ((TextBox)sender).GotFocus -= txtKey_GotFocus;
                KeyChanged = true;
            }
            else
            {
                var result = MessageBox.Show("Are you sure you want to clear the current key?. ", "Warning", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning);

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
                {
                    txtSourceFile.Focus();
                }
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
            var dlg = new OpenFileDialog
            {
                DefaultExt = ".txt",
                InitialDirectory = @"C:\"
            };
            
            var result = dlg.ShowDialog();

            if (result.HasValue && result.Value)
            {
                txtSourceFile.Text = dlg.FileName;
                var extension = System.IO.Path.GetExtension(txtSourceFile.Text); // pobieram rozszerzenie, że ścieżki pliku

                if (extension != ".serpent") // aktualizuję pole rozszerzenia pliku
                {
                    var key = serpent.RandomizeKey(); // wywołuję metodę losującą klucze, jeżli użytkownik dodał plik. 
                    UpdateGuiWithRandomizedKeys(key);
                }
            }
        }

        private void txtSourceFile_Drop(object sender, DragEventArgs e) // obsługa operacji drag and drop
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) // ustawiam wartość ścieżki jako ścieżkę przeciągniętego pliku
            {
                var files = (string[])e.Data.GetData(DataFormats.FileDrop);
                txtSourceFile.Text = files[0];

                var extension = System.IO.Path.GetExtension(txtSourceFile.Text); // pobieram rozszerzenie, że ścieżki pliku

                if (extension != ".serpent") // aktualizuję pole rozszerzenia pliku
                {
                    var key = serpent.RandomizeKey(); // wywołuję metodę losującą klucze, jeżli użytkownik przeciągnał plik. 
                    UpdateGuiWithRandomizedKeys(key);
                }
            }
        }

        private void UpdateGuiWithRandomizedKeys(byte[] key)
        {
            var vd = new Validation();

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
            var extension = System.IO.Path.GetExtension(txtSourceFile.Text); 

            if (extension != ".serpent")
            {
                txtKey.Text = string.Empty;
                var key = serpent.RandomizeKey();
                UpdateGuiWithRandomizedKeys(key);
            }
            else
            {
                if (!string.IsNullOrEmpty(txtKey.Text))
                {
                    var result = MessageBox.Show("Current key will be lost, are you sure you want to continue? ", "Error", MessageBoxButton.YesNo, MessageBoxImage.Warning);

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
            var extension = Path.GetExtension(txtSourceFile.Text);

            if (extension != ".serpent")
            {
                txtKey.Text = string.Empty;
                var key = serpent.RandomizeKey();
                UpdateGuiWithRandomizedKeys(key);
            }
            else
            {
                if (!string.IsNullOrEmpty(txtKey.Text))
                {
                    var result = MessageBox.Show("Current key will be lost, are you sure you want to continue? ", "Error", MessageBoxButton.YesNo, MessageBoxImage.Warning);

                    if (result == MessageBoxResult.Yes)
                    {
                        txtKey.Text = string.Empty;
                    }
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
            var vd = new Validation();
            Brush green = new SolidColorBrush(Color.FromArgb(0xFF, 0x70, 0x8C, 0x00));
            Brush red = new SolidColorBrush(Color.FromArgb(0xFF, 0xE0, 0x51, 0x51));

            var vdResult = vd.ValidateForm(this, ActionType.ChangingText, out List<object> validationResults);

            if (vdResult || (byte[]) validationResults?[0] != null)
            {
                var key = (byte[])validationResults[0];

                lblKeyValidation.Foreground = vdResult ? green : red;
                lblKeyValidation.Content = $"Key: {key.Length * 8} bit{vd.GetWordEnding(key.Length * 8)} ({key.Length} byte{vd.GetWordEnding(key.Length)}) ({(vdResult ? "Correct" : "Incorrect")})";
            }
        }

        private void ModifyGuiVisibility(OperationStatus Status, object sender)
        {
            if (Status == OperationStatus.Start)
            {
                lblOperation.Visibility = Visibility.Visible;

                var btn = (Button) sender;
                foreach (FrameworkElement item in ((Panel)btn.Parent).Children) // wyłączam pola formularza podczas operacji szyfrowania
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
                        if (item as TextBox == txtRounds && rbBitSliceMode.IsChecked == true)
                            (item as TextBox).IsReadOnly = true;
                        else
                            (item as TextBox).IsReadOnly = false;
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
                ResizeMode = ResizeMode.CanResize;
            }
            else if (cbUnlockResize.IsChecked == false)
            {
                ResizeMode = ResizeMode.CanMinimize;
                SizeToContent = SizeToContent.WidthAndHeight;
            }
        }

        private void btnGenerateKey_Click(object sender, RoutedEventArgs e)
        {
            txtKey.Text = string.Empty;
            var key = serpent.RandomizeKey();
            UpdateGuiWithRandomizedKeys(key);
        }

        private void mainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e) { }

        private void btnMinimizeToTray_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
            ShowInTaskbar = false;
            _notifyIcon.Visible = true;
            _notifyIcon.ShowBalloonTip(1500);
        }

        private void btnMinimizeToTray_MouseEnter(object sender, MouseEventArgs e)
        {
            ((Button)sender).Background = new SolidColorBrush(Color.FromRgb(0, 0, 180));
        }

        private void btnMinimizeToTray_MouseLeave(object sender, MouseEventArgs e)
        {
            ((Button)sender).Background = Brushes.Transparent;
        }

        private void btnMinimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void btnMinimize_MouseEnter(object sender, MouseEventArgs e)
        {
            ((Button)sender).Background = new SolidColorBrush(Color.FromRgb(76, 76, 76));
        }

        private void btnMinimize_MouseLeave(object sender, MouseEventArgs e)
        {
            ((Button)sender).Background = Brushes.Transparent;
        }

        private void btnClose_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void btnClose_MouseEnter(object sender, MouseEventArgs e)
        {
            ((Button)sender).Background = new SolidColorBrush(Color.FromRgb(76, 76, 76));
            ((Button)sender).Foreground = Brushes.Black;
        }

        private void btnClose_MouseLeave(object sender, MouseEventArgs e)
        {
            ((Button)sender).Background = Brushes.Transparent;
            ((Button)sender).Foreground = Brushes.White;
        }

        private bool _restoreForDragMove;

        private void gridTitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2)
            {
                if (ResizeMode != ResizeMode.CanResize && ResizeMode != ResizeMode.CanResizeWithGrip)
                    return;

                WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
            }
            else
            {
                _restoreForDragMove = WindowState == WindowState.Maximized;
                DragMove();
            }
        }

        private void gridTitleBar_MouseMove(object sender, MouseEventArgs e)
        {
            if (_restoreForDragMove && e.LeftButton == MouseButtonState.Pressed)
            {
                _restoreForDragMove = false;

                var wndMousePos = e.MouseDevice.GetPosition(this);
                var screenMousePos = this.WindowPointToScreen(wndMousePos);

                Left = screenMousePos.X - Width / (ActualWidth / wndMousePos.X);
                Top = screenMousePos.Y - Height / (ActualHeight / wndMousePos.Y);

                WindowState = WindowState.Normal;

                DragMove();
            }
        }

        private void gridTitleBar_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            _restoreForDragMove = false;
        }

        private void gridTitleBar_MouseEnter(object sender, MouseEventArgs e)
        {
            ((Grid)sender).Highlight(((SolidColorBrush)FindResource("MouseOverTitleBarBrush")).Color);
        }

        private void gridTitleBar_MouseLeave(object sender, MouseEventArgs e)
        {
            ((Grid)sender).Highlight(((SolidColorBrush)FindResource("DefaultWindowBrush")).Color);
        }

        private void notifyIcon_Click(object sender, EventArgs e)
        {
            ShowInTaskbar = true;
            _notifyIcon.Visible = false;
            WindowState = WindowState.Normal;

            if (IsVisible)
                Activate();
            else
                Show();
        }
    }

    public enum OperationStatus
    {
        Start,
        End
    }
}
