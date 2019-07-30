using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace WPFSerpent.Source.Models
{
    public class Validation
    {
        public bool ValidateForm(Control FormToValidate, ActionType Operation, out List<object> ValidationResults)
        {
            var strKey = ((TextBox) FormToValidate.FindName("txtKey"))?.Text;
            var keyMode = ((RadioButton) FormToValidate.FindName("rbKeyBytes"))?.IsChecked == true ? KeyMode.Bytes : KeyMode.Chars;
            int rounds;
            byte[] key;

            if (Operation == ActionType.Encryption)
            {
                if (CheckIfFileHasBeenChosen(FormToValidate)) // sprawdź czy wybranmo plik
                    if (CheckIfFileIsNotEncryptedAlready(FormToValidate)) // sprawdź czy plik nie jest już zaszyfrowany
                        if (CheckIfRoundsAreParsable(FormToValidate, out rounds))
                            if (CheckIfRoundsAreValid(rounds))
                                if (CheckIfModeIsValid(FormToValidate))
                                    if (!CheckIfKeyIsEmpty(FormToValidate))
                                        if (CheckIfKeyIsValid(strKey, keyMode, out key)) // sprawdź poprawność klucza
                                        {
                                            ValidationResults = new List<object>
                                            {
                                                key,
                                                rounds
                                            };
                                            return true;
                                        }
                                        else
                                        {
                                            MessageBox.Show("This is not a correct key format. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                                        }
                                    else
                                        MessageBox.Show("Key is empty. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                                else
                                    MessageBox.Show("Cipher mode has not been selected. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                            else
                                MessageBox.Show("Number of rounds is incorrect. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        else
                            MessageBox.Show("Rounds value is not a number. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    else
                        MessageBox.Show("File is already encrypted. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                else
                    MessageBox.Show("No file has been selected. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else if (Operation == ActionType.Decryption)
            {
                if (CheckIfFileHasBeenChosen(FormToValidate))
                    if (CheckIfFileIsNotDecryptedAlready(FormToValidate)) // sprawdź czy plik nie jest już odszyfrowany
                        if (CheckIfRoundsAreParsable(FormToValidate, out rounds))
                            if (CheckIfRoundsAreValid(rounds))
                                if (CheckIfModeIsValid(FormToValidate))
                                    if (!CheckIfKeyIsEmpty(FormToValidate))
                                        if (CheckIfKeyIsValid(strKey, keyMode, out key)) // sprawdź poprawność klucza 'A' (czy wartości tworzą macierz odwracalną)
                                        {
                                            ValidationResults = new List<object>
                                            {
                                                key,
                                                rounds
                                            };
                                            return true;
                                        }
                                        else
                                        {
                                            MessageBox.Show("This is not a correct Key format. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                                        }
                                    else
                                        MessageBox.Show("Key is empty. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                                else
                                    MessageBox.Show("Cipher Mode has not been selected. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                            else
                                MessageBox.Show("Incorrect number of rounds. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        else
                            MessageBox.Show("Rounds value is not a number. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    else
                        MessageBox.Show("File is not encrypted. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                else
                    MessageBox.Show("File has not been chosen. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else if (Operation == ActionType.ChangingText)
            {
                var lblKeyValidation = (Label) FormToValidate.FindName("lblKeyValidation");
                if (lblKeyValidation == null)
                    throw new NullReferenceException($"{nameof(lblKeyValidation)}");
                Brush red = new SolidColorBrush(Color.FromArgb(0xFF, 0xE0, 0x51, 0x51));

                if (CheckIfFileHasBeenChosen(FormToValidate)) // sprawdź czy wybranmo plik
                {
                    if (CheckIfRoundsAreParsable(FormToValidate, out rounds))
                    {
                        if (CheckIfRoundsAreValid(rounds))
                        {
                            if (CheckIfModeIsValid(FormToValidate))
                            {
                                if (!CheckIfKeyIsEmpty(FormToValidate))
                                {
                                    if (CheckIfKeyIsValid(strKey, keyMode, out key)) // sprawdź poprawność klucza
                                    {
                                        ValidationResults = new List<object>
                                        {
                                            key,
                                            rounds
                                        };
                                        return true;
                                    }
                                    if (key == null)
                                    {
                                        lblKeyValidation.Content = "This is not a correct key in " + (keyMode == KeyMode.Bytes ? "comma delimited bytes" : "UTF-8 format");
                                        lblKeyValidation.Foreground = red;
                                    }
                                    else
                                    {
                                        ValidationResults = new List<object>
                                        {
                                            key
                                        };
                                        return false;
                                    }
                                }
                                else
                                {
                                    lblKeyValidation.Content = "Key is empty";
                                    lblKeyValidation.Foreground = red;
                                }
                            }
                            else
                            {
                                lblKeyValidation.Content = "Cipher mode has not been chosen";
                                lblKeyValidation.Foreground = red;
                            }
                        }
                        else
                        {
                            lblKeyValidation.Content = "Incorrect number of rounds";
                            lblKeyValidation.Foreground = red;
                        }
                    }
                    else
                    {
                        lblKeyValidation.Content = "Rounds value is not a number";
                        lblKeyValidation.Foreground = red;
                    }
                }
                else
                {
                    lblKeyValidation.Content = "No file has been selected";
                    lblKeyValidation.Foreground = red;
                }
            }

            ValidationResults = null;
            return false;
        }

        private static bool CheckIfModeIsValid(Control FormToValidate)
        {
            var rbBitSliceMode = (RadioButton) FormToValidate.FindName("rbBitSliceMode");
            var rbStandardMode = (RadioButton) FormToValidate.FindName("rbStandardMode");

            return rbBitSliceMode?.IsChecked != rbStandardMode?.IsChecked;
        }

        private static bool CheckIfRoundsAreValid(int rounds)
        {
            return rounds <= 64 && rounds > 0;
        }

        private static bool CheckIfRoundsAreParsable(FrameworkElement FormToValidate, out int Rounds)
        {
            var txtRounds = (TextBox) FormToValidate.FindName("txtRounds");
            if (txtRounds == null) throw new NullReferenceException();
            var rgxPattern = new Regex("^[0-9]+$");

            return
                int.TryParse(txtRounds.Text, out Rounds) && rgxPattern.IsMatch(txtRounds.Text);
        }

        private static bool CheckIfFileHasBeenChosen(FrameworkElement FormToValidate)
        {
            var txtSourceFile = (TextBox)FormToValidate.FindName("txtSourceFile");
            if (txtSourceFile == null) throw new NullReferenceException();
            return !string.IsNullOrEmpty(txtSourceFile.Text) && txtSourceFile.Text != "Select or drop a file...";
        }

        private static bool CheckIfFileIsNotEncryptedAlready(FrameworkElement FormToValidate)
        {
            var txtSourceFile = (TextBox)FormToValidate.FindName("txtSourceFile");
            if (txtSourceFile == null) throw new NullReferenceException();
            return
                Path.GetExtension(txtSourceFile.Text.ToLower()) != ".serpent";
        }

        private static bool CheckIfFileIsNotDecryptedAlready(FrameworkElement FormToValidate)
        {
            var txtSourceFile = (TextBox)FormToValidate.FindName("txtSourceFile");
            if (txtSourceFile == null) throw new NullReferenceException();
            return
                Path.GetExtension(txtSourceFile.Text.ToLower()) == ".serpent";
        }

        private static bool CheckIfKeyIsValid(string StrKey, KeyMode KeyMode, out byte[] Key)
        {
            Encoding enc = new UTF8Encoding();
            Key = null;
            StrKey = StrKey.Replace(" ", "");

            if (KeyMode == KeyMode.Chars)
            {
                Key = enc.GetBytes(StrKey); // pozostaw na null jeśli tablica ma zero bajtów (żeby mieć niepoprawny klucz)

                if (Key.Length == 0)
                {
                    Key = null;
                    return false;
                }
            }
            else if (KeyMode == KeyMode.Bytes)
            {
                var listKeyBytes = new List<byte>();
                var sb = new StringBuilder();

                for (var i = 0; i <= StrKey.Length; i++)
                {
                    if (i < StrKey.Length && int.TryParse(StrKey[i].ToString(), out int num))
                    {
                        sb.Append(num);
                    }
                    else if (sb.Length > 0) // jeśli na końcu jest przecinek to trzeba też sprawdzić czy sb coś zawiera, żeby nie próbowało sparsować czegoś pustego
                    {
                        num = int.Parse(sb.ToString());

                        if (num <= byte.MaxValue && (i == StrKey.Length || StrKey[i] == ',')) // indeks wykroczy poza tablicę, alepętla przechodzi jeszcze raz tylko po to, żeby sparsować ostatnią wartość, najpierw sprawdzam warunek długości, bo drugiego warunku nigdy nie sprawdzi przy ostatnim przejściu i nie wyrzuci błędu
                        {
                            listKeyBytes.Add((byte)num);
                            sb.Clear();
                        }
                        else
                        {
                            return false;
                        }
                    }
                    else if (i == StrKey.Length && StrKey[i - 1] == ',' && listKeyBytes.Count > 0)
                    {
                        break;
                    }
                    else
                    {
                        return false;
                    }
                }

                Key = listKeyBytes.ToArray();
            }
            else
            {
                return false;
            }

            return
                Key.Length % 4 == 0 && Key.Length / 4 <= 8;
        }

        public bool CheckIfKeyIsEmpty(Control FormToValidate)
        {
            var txtKey = (TextBox) FormToValidate.FindName("txtKey");

            return
                string.IsNullOrEmpty(txtKey?.Text) || txtKey.Text == "key...";
        }

        public string GetKeyString(byte[] key, KeyMode keyMode)
        {
            var sb = new StringBuilder();

            if (keyMode == KeyMode.Bytes)
            {
                foreach (var b in key)
                    sb.Append(b + ", ");

                return sb.ToString().Remove(sb.ToString().Length - 2);
            }
            if (keyMode == KeyMode.Chars)
            {
                const string avlChars = "aąbcćdeęfghijklmnoópqrstuvwxyzżźAĄBCĆDEĘFGHIJKLMNOÓPQRSTUVWXYZŻŹ~!@#$%^&*()-_=+,./;\'[]<>?:\"|\\{}";
                var enc = new UTF8Encoding();
                var b = 0;

                while (enc.GetByteCount(sb.ToString()) != key.Length)
                {
                    sb.Append(avlChars[key[b++ % key.Length] % avlChars.Length]);

                    while (enc.GetByteCount(sb.ToString()) > key.Length)
                        sb.Length--;
                }

                return sb.ToString();
            }
            throw new Exception("Incorrect way of key input. ");
        }

        public bool CheckIfRoundsNumIsEmpty(Control FormToValidate)
        {
            var txtRounds = (TextBox) FormToValidate.FindName("txtRounds");

            return
                string.IsNullOrEmpty(txtRounds?.Text) || txtRounds.Text == "rounds...";
        }

        public string GetWordEnding(int n) => n > 1 ? "s" : "";
    }
}
