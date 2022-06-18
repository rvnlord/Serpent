using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Forms;
using System.Windows.Input;
using System.Windows.Media;
using WpfSerpent.Source.Common.Extensions;
using WpfSerpent.Source.Models;
using Brush = System.Windows.Media.Brush;
using Brushes = System.Windows.Media.Brushes;
using Button = System.Windows.Controls.Button;
using Color = System.Windows.Media.Color;
using DataFormats = System.Windows.DataFormats;
using DragDropEffects = System.Windows.DragDropEffects;
using DragEventArgs = System.Windows.DragEventArgs;
using MessageBox = System.Windows.MessageBox;
using MouseEventArgs = System.Windows.Input.MouseEventArgs;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;
using Panel = System.Windows.Controls.Panel;
using RadioButton = System.Windows.Controls.RadioButton;
using TextBox = System.Windows.Controls.TextBox;
using Validation = WpfSerpent.Source.Models.Validation;

namespace WpfSerpent.Source.Windows
{
    public partial class MainWindow
    {
        private NotifyIcon _notifyIcon;

        private readonly Stopwatch sw = new();

        private SerpentCipher serpent = new(); // inicjalizuję obiekt klasy szyfrującej
        private readonly BackgroundWorker bgwEncrypt = new(); // inicjalizuję klasy obsługujące szyfreowanie asynchronicznie
        private readonly BackgroundWorker bgwDecrypt = new();

        private bool KeyChanged { get; set; } // deklaruję właściwości
        private bool RoundsChanged { get; set; }

        public MainWindow()
        {
            InitializeComponent();
            Loaded += MainWindow_Loaded; // dodaję event handler, który będzie wyzwalany przy załadowaniu interfejsu użytkownika
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            Icon icon = null;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var iconHandle = WpfSerpent.Properties.Resources.NotifyIcon.GetHicon();
                icon = System.Drawing.Icon.FromHandle(iconHandle);
            }
            
            _notifyIcon = new NotifyIcon
            {
                BalloonTipTitle = lblWindowTitle.Content.ToString(),
                BalloonTipText = @"is hidden here",
                Icon = icon
            };
            _notifyIcon.Click += NotifyIcon_Click;
            
            serpent.EncryptionProgressChanged += MainWindow_EncryptionProgressChanged; // uzupełniam zmienne klasy szyfrującej
            pbStatus.Visibility = Visibility.Collapsed;
            txtbStatus.Visibility = Visibility.Collapsed;
            lblOperation.Visibility = Visibility.Collapsed;

            bgwEncrypt.WorkerReportsProgress = true; // dodaję event handlery do klas działających asynchronicznie
            bgwEncrypt.DoWork += BgwEncrypt_DoWork;
            bgwEncrypt.ProgressChanged += BgwEncryptDecrypt_ProgressChanged;
            bgwEncrypt.RunWorkerCompleted += BgwEncrypt_RunWorkerCompleted;

            bgwDecrypt.WorkerReportsProgress = true;
            bgwDecrypt.DoWork += BgwDecrypt_DoWork;
            bgwDecrypt.ProgressChanged += BgwEncryptDecrypt_ProgressChanged;
            bgwDecrypt.RunWorkerCompleted += BgwDecrypt_RunWorkerCompleted;

            KeyChanged = RoundsChanged = false; // inicjalizuję właściwości
            
            rbKeyBytes.IsChecked = true;
            rbECBEncrMode.IsChecked = true;

            rbKeyChars.Checked += RbKeyChars_Checked;
            rbKeyBytes.Checked += RbKeyBytes_Checked;
            txtKey.TextChanged += TxtKey_TextChanged;
            txtSourceFile.TextChanged += TxtSourceFile_TextChanged;
            txtRounds.TextChanged += TxtRounds_TextChanged;
            rbBitSliceMode.Checked += RbBitSliceMode_Checked;
            rbStandardMode.Checked += RbStandardMode_Checked;

            rbBitSliceMode.IsChecked = true;

            lblKeyValidation.Content = string.Empty;
        }

        private void BtnEncrypt_Click(object sender, RoutedEventArgs e)
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

        private void BgwEncrypt_DoWork(object sender, DoWorkEventArgs e)
        {
            serpent = new SerpentCipher();
            serpent.EncryptionProgressChanged += MainWindow_EncryptionProgressChanged; 
            var key = (byte[])((object[])(e.Argument ?? throw new NullReferenceException()))[0]; 
            var sourceFile = ((object[])e.Argument)[1].ToString();
            var rounds = (int)((object[])e.Argument)[2];
            var algMode = (Mode)((object[])e.Argument)[3];
            var encrMode = (EncryptionMode)((object[])e.Argument)[4];
            var flag = serpent.Encrypt(sourceFile, key, rounds, algMode, encrMode); 
            e.Result = flag;
        }

        private void BgwEncrypt_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            sw.Stop();
            UpdateGuiOnCompletion($"File has been correctly Encrypted (Time: {sw.Elapsed}). ", sender, e); // przekazuję wiadomość i wynik operacji szyfrowania do metody aktualizującej interfejs użytkownika.
            sw.Reset();
        }

        private void BtnDecrypt_Click(object sender, RoutedEventArgs e)
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

        private void BgwDecrypt_DoWork(object sender, DoWorkEventArgs e)
        {
            serpent = new SerpentCipher(); // initialize the encrypting class with length of the alphabet
            serpent.EncryptionProgressChanged += MainWindow_EncryptionProgressChanged; // subscribe to the event handler in order to manage progress
            var key = (byte[])((object[])(e.Argument ?? throw new NullReferenceException()))[0]; // retrieve and type cast parameters of the operation
            var sourceFile = ((object[])e.Argument)[1].ToString();
            var rounds = (int)((object[])e.Argument)[2];
            var algMode = (Mode)((object[])e.Argument)[3];
            var encrMode = (EncryptionMode)((object[])e.Argument)[4];
            var flag = serpent.Decrypt(sourceFile, key, rounds, algMode, encrMode); // start LONG RUNNING decryption process
            e.Result = flag; // pass the decryption status into the event that comes next.
        }

        private void BgwDecrypt_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            sw.Stop();
            UpdateGuiOnCompletion($"File has been correctly Decrypted (Time: {sw.Elapsed}). ", sender, e); // pass a message with decryption result to the mthod updating user interface
            sw.Reset();
        }

        private void UpdateGuiOnCompletion(string Message, object sender, RunWorkerCompletedEventArgs e)
        {
            var opResult = (bool)(e.Result ?? throw new NullReferenceException()); 

            if (opResult)
                MessageBox.Show(Message, "Success", MessageBoxButton.OK, MessageBoxImage.Information);

            ModifyGuiVisibility(OperationStatus.End, sender);
            ModifyGuiEventHandlers(OperationStatus.End);
        }

        private void MainWindow_EncryptionProgressChanged(object sender, EncryptionProgressChangedEventArgs e) // zdarzenie wywoływane jest przy każdej iteracji metody szyfrującej, dla każdej części pliku
        {
            switch (e.ActionType) // przekazuję postęp operacji szyfrującej lub deszyfrującej do domyślnego zdarzenia wywoływanego przez drugi wątek przy aktualizacji postępu jednocześnie wywołując to zdarzenie
            {
                case ActionType.Encryption:
                    bgwEncrypt.ReportProgress(e.Progress);
                    break;
                case ActionType.Decryption:
                    bgwDecrypt.ReportProgress(e.Progress);
                    break;
                case ActionType.ChangingText:
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(e));
            }
        }

        private void BgwEncryptDecrypt_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            pbStatus.Value = e.ProgressPercentage; // aktualizuję pasek postępu operacji

            lblOperation.Foreground = e.ProgressPercentage > 33 ? Brushes.Blue : Brushes.White;
            txtbStatus.Foreground = e.ProgressPercentage > 50 ? Brushes.Blue : Brushes.White;
        }

        private void BtnClear_Click(object sender, RoutedEventArgs e)
        {
            txtKey.Text = "key...";
            txtKey.GotFocus += TxtKey_GotFocus;
            KeyChanged = false;
            txtKey.FontStyle = FontStyles.Italic;

            if (rbBitSliceMode.IsChecked == false)
                txtRounds.Text = "rounds...";

            txtRounds.GotFocus += TxtRounds_GotFocus;
            RoundsChanged = false;
            txtRounds.FontStyle = FontStyles.Italic;

            txtSourceFile.Text = "Select or drop a file...";
        }

        private void TxtKey_GotFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(txtKey.Text) || txtKey.Text == "key...")
            {
                FormatTextBoxOnFocus((TextBox)sender);
                ((TextBox)sender).GotFocus -= TxtKey_GotFocus;
                KeyChanged = true;
            }
            else
            {
                var result = MessageBox.Show("Are you sure you want to clear the current key?. ", "Warning", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    FormatTextBoxOnFocus((TextBox)sender);
                    ((TextBox)sender).GotFocus -= TxtKey_GotFocus;
                    KeyChanged = true;
                }
                else if (result == MessageBoxResult.No)
                {
                    ((TextBox)sender).FontStyle = FontStyles.Normal;
                    ((TextBox)sender).GotFocus -= TxtKey_GotFocus;
                    KeyChanged = true;
                }
                else if (result == MessageBoxResult.Cancel)
                {
                    txtSourceFile.Focus();
                }
            }
        }

        private void TxtRounds_GotFocus(object sender, RoutedEventArgs e)
        {
            if (((TextBox)sender).IsReadOnly == false)
            {
                FormatTextBoxOnFocus((TextBox)sender);
                ((TextBox)sender).GotFocus -= TxtRounds_GotFocus;
                RoundsChanged = true;
            }
        }

        private static void FormatTextBoxOnFocus(TextBox txtB)
        {
            txtB.Text = string.Empty;
            txtB.FontWeight = FontWeights.Normal;
            txtB.FontStyle = FontStyles.Normal;
        }

        private void BtnChooseSourceFile_Click(object sender, RoutedEventArgs e)
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
                    var key = SerpentCipher.RandomizeKey(); // wywołuję metodę losującą klucze, jeżli użytkownik dodał plik. 
                    UpdateGuiWithRandomizedKeys(key);
                }
            }
        }

        private void TxtSourceFile_Drop(object sender, DragEventArgs e) // obsługa operacji drag and drop
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) // ustawiam wartość ścieżki jako ścieżkę przeciągniętego pliku
            {
                var files = (string[])e.Data.GetData(DataFormats.FileDrop);
                txtSourceFile.Text = files?[0] ?? throw new NullReferenceException();

                var extension = Path.GetExtension(txtSourceFile.Text); // pobieram rozszerzenie, że ścieżki pliku

                if (extension != ".serpent") // aktualizuję pole rozszerzenia pliku
                {
                    var key = SerpentCipher.RandomizeKey(); // wywołuję metodę losującą klucze, jeżli użytkownik przeciągnał plik. 
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

        private void TxtSourceFile_DragEnter(object sender, DragEventArgs e)
        {
            e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.All : DragDropEffects.None;
        }

        private void TxtSourceFile_PreviewDragOver(object sender, DragEventArgs e)
        {
            e.Handled = true; // linijka wymagana, żeby drag and drop działał
        }

        private void TxtSourceFile_TextChanged(object sender, TextChangedEventArgs e)
        {
            PerformTextChangedValidation();
        }

        private void TxtRounds_TextChanged(object sender, TextChangedEventArgs e)
        {
            PerformTextChangedValidation();
        }

        private void TxtKey_TextChanged(object sender, TextChangedEventArgs e)
        {
            PerformTextChangedValidation();
        }

        private void RbKeyChars_Checked(object sender, RoutedEventArgs e)
        {
            var extension = Path.GetExtension(txtSourceFile.Text); 

            if (extension != ".serpent")
            {
                txtKey.Text = string.Empty;
                var key = SerpentCipher.RandomizeKey();
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
                        rbKeyBytes.Checked -= RbKeyBytes_Checked;
                        rbKeyBytes.IsChecked = true;
                        rbKeyBytes.Checked += RbKeyBytes_Checked;
                    }
                }
            }

            PerformTextChangedValidation();
        }

        private void RbKeyBytes_Checked(object sender, RoutedEventArgs e)
        {
            var extension = Path.GetExtension(txtSourceFile.Text);

            if (extension != ".serpent")
            {
                txtKey.Text = string.Empty;
                var key = SerpentCipher.RandomizeKey();
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
                        rbKeyChars.Checked -= RbKeyChars_Checked;
                        rbKeyChars.IsChecked = true;
                        rbKeyChars.Checked += RbKeyChars_Checked;
                    }
                }
            }

            PerformTextChangedValidation();
        }

        private void RbStandardMode_Checked(object sender, RoutedEventArgs e)
        {
            txtRounds.IsReadOnly = false;
        }

        private void RbBitSliceMode_Checked(object sender, RoutedEventArgs e)
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
            switch (Status)
            {
                case OperationStatus.Start:
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
                    break;
                }
                case OperationStatus.End:
                {
                    lblOperation.Visibility = Visibility.Collapsed;
                    lblOperation.Foreground = Brushes.White;

                    pbStatus.Visibility = Visibility.Collapsed;
                    txtbStatus.Visibility = Visibility.Collapsed;
                    pbStatus.Value = 0;

                    foreach (FrameworkElement item in ((Panel)btnEncrypt.Parent).Children)
                        switch (item)
                        {
                            // aktualizuję widoczność paneli
                            case Button:
                                item.IsEnabled = true;
                                break;
                            case TextBox box when box == txtRounds && rbBitSliceMode.IsChecked == true:
                                box.IsReadOnly = true;
                                break;
                            case TextBox box:
                                box.IsReadOnly = false;
                                break;
                            case RadioButton button:
                                button.IsEnabled = true;
                                break;
                        }

                    txtSourceFile.IsReadOnly = true;
                    txtSourceFile.Visibility = Visibility.Visible;
                    btnChooseSourceFile.Visibility = Visibility.Visible;

                    lblMode.Opacity = 1.0;
                    lblKeyMode.Opacity = 1.0;
                    lblEncrMode.Opacity = 1.0;
                    break;
                }
                default:
                    throw new ArgumentOutOfRangeException(nameof(Status), Status, null);
            }
        }

        private void ModifyGuiEventHandlers(OperationStatus Status)
        {
            switch (Status)
            {
                case OperationStatus.Start:
                {
                    if (!KeyChanged) // usuwam event handlery czyszczące pola formularza, jeżeli użytkownik przeciągając plik wygenerował je automatycznie
                        txtKey.GotFocus -= TxtKey_GotFocus;
                    if (!RoundsChanged)
                        txtRounds.GotFocus -= TxtRounds_GotFocus;
                    break;
                }
                case OperationStatus.End:
                {
                    if (!KeyChanged) // dodaję z powrotem event handlery, jeżeli pola formularza zostały przed operacją wygenerowane automatycznie poprzez przeciągnięcie pliku
                        txtKey.GotFocus += TxtKey_GotFocus;
                    if (!RoundsChanged)
                        txtRounds.GotFocus += TxtRounds_GotFocus;
                    break;
                }
                default:
                    throw new ArgumentOutOfRangeException(nameof(Status), Status, null);
            }
        }

        private void CbUnlockResize_Click(object sender, RoutedEventArgs e)
        {
            switch (cbUnlockResize.IsChecked)
            {
                case true:
                    ResizeMode = ResizeMode.CanResize;
                    break;
                case false:
                    ResizeMode = ResizeMode.CanMinimize;
                    SizeToContent = SizeToContent.WidthAndHeight;
                    break;
            }
        }

        private void BtnGenerateKey_Click(object sender, RoutedEventArgs e)
        {
            txtKey.Text = string.Empty;
            var key = SerpentCipher.RandomizeKey();
            UpdateGuiWithRandomizedKeys(key);
        }

        private void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e) { }

        private void BtnMinimizeToTray_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
            ShowInTaskbar = false;
            _notifyIcon.Visible = true;
            _notifyIcon.ShowBalloonTip(1500);
        }

        private void BtnMinimizeToTray_MouseEnter(object sender, MouseEventArgs e)
        {
            ((Button)sender).Background = new SolidColorBrush(Color.FromRgb(0, 0, 180));
        }

        private void BtnMinimizeToTray_MouseLeave(object sender, MouseEventArgs e)
        {
            ((Button)sender).Background = Brushes.Transparent;
        }

        private void BtnMinimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void BtnMinimize_MouseEnter(object sender, MouseEventArgs e)
        {
            ((Button)sender).Background = new SolidColorBrush(Color.FromRgb(76, 76, 76));
        }

        private void BtnMinimize_MouseLeave(object sender, MouseEventArgs e)
        {
            ((Button)sender).Background = Brushes.Transparent;
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void BtnClose_MouseEnter(object sender, MouseEventArgs e)
        {
            ((Button)sender).Background = new SolidColorBrush(Color.FromRgb(76, 76, 76));
            ((Button)sender).Foreground = Brushes.Black;
        }

        private void BtnClose_MouseLeave(object sender, MouseEventArgs e)
        {
            ((Button)sender).Background = Brushes.Transparent;
            ((Button)sender).Foreground = Brushes.White;
        }

        private bool _restoreForDragMove;

        private void GridTitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
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

        private void GridTitleBar_MouseMove(object sender, MouseEventArgs e)
        {
            if (!_restoreForDragMove || e.LeftButton != MouseButtonState.Pressed) 
                return;

            _restoreForDragMove = false;

            var wndMousePos = e.MouseDevice.GetPosition(this);
            var screenMousePos = this.WindowPointToScreen(wndMousePos);

            Left = screenMousePos.X - Width / (ActualWidth / wndMousePos.X);
            Top = screenMousePos.Y - Height / (ActualHeight / wndMousePos.Y);

            WindowState = WindowState.Normal;

            DragMove();
        }

        private void GridTitleBar_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            _restoreForDragMove = false;
        }

        private void GridTitleBar_MouseEnter(object sender, MouseEventArgs e)
        {
            ((Grid)sender).Highlight(((SolidColorBrush)FindResource("MouseOverTitleBarBrush")).Color);
        }

        private void GridTitleBar_MouseLeave(object sender, MouseEventArgs e)
        {
            ((Grid)sender).Highlight(((SolidColorBrush)FindResource("DefaultWindowBrush")).Color);
        }

        private void NotifyIcon_Click(object sender, EventArgs e)
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
