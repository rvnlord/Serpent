using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace WpfDemo
{
    class Validation
    {
        SerpentCipher serpent = new SerpentCipher();

        public Validation()
        {
            serpent.AlphabetLength = 256;
        }

        public bool ValidateForm(Control FormToValidate, ActionType Operation, out List<object> ValidationResults)
        {
            string strKey = ((TextBox)FormToValidate.FindName("txtKey")).Text;
            KeyMode keyMode = ((RadioButton)FormToValidate.FindName("rbKeyBytes")).IsChecked == true ? KeyMode.Bytes : KeyMode.Chars;
            int rounds = 0;
            byte[] key = null;

            if (Operation == ActionType.Encryption)
            {
                if (CheckIfFileHasBeenChosen(FormToValidate)) // sprawdź czy wybranmo plik
                {
                    if (CheckIfFileIsNotEncryptedAlready(FormToValidate)) // sprawdź czy plik nie jest już zaszyfrowany
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
                                            ValidationResults = new List<object> { key, rounds };
                                            return true;
                                        }
                                        else
                                            MessageBox.Show("To nie jest poprawny format klucza. ", "Błąd", MessageBoxButton.OK, MessageBoxImage.Error);
                                    }
                                    else
                                        MessageBox.Show("Klucz jest pusty. ", "Błąd", MessageBoxButton.OK, MessageBoxImage.Error);
                                }
                                else
                                    MessageBox.Show("Nie wybrano sposobu szyfrowania. ", "Błąd", MessageBoxButton.OK, MessageBoxImage.Error);
                            }
                            else
                                MessageBox.Show("Ilość rund jest nieprawidłowa. ", "Błąd", MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                        else
                            MessageBox.Show("Ilość rund musi być liczbą. ", "Błąd", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                    else
                        MessageBox.Show("Plik jest już zaszyfrowany. ", "Błąd", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                else
                    MessageBox.Show("Nie wybrano zadnego pliku. ", "Błąd", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else if (Operation == ActionType.Decryption)
            {
                if (CheckIfFileHasBeenChosen(FormToValidate))
                {
                    if (CheckIfFileIsNotDecryptedAlready(FormToValidate)) // sprawdź czy plik nie jest już odszyfrowany
                    {
                        if (CheckIfRoundsAreParsable(FormToValidate, out rounds))
                        {
                            if (CheckIfRoundsAreValid(rounds))
                            {
                                if (CheckIfModeIsValid(FormToValidate))
                                {
                                    if (!CheckIfKeyIsEmpty(FormToValidate))
                                    {
                                        if (CheckIfKeyIsValid(strKey, keyMode, out key)) // sprawdź poprawność klucza 'A' (czy wartości tworzą macierz odwracalną)
                                        {
                                            ValidationResults = new List<object> { key, rounds };
                                            return true;
                                        }
                                        else
                                            MessageBox.Show("To nie jest poprawny format klucza. ", "Błąd", MessageBoxButton.OK, MessageBoxImage.Error);
                                    }
                                    else
                                        MessageBox.Show("Klucz jest pusty. ", "Błąd", MessageBoxButton.OK, MessageBoxImage.Error);
                                }
                                else
                                    MessageBox.Show("Nie wybrano sposobu szyfrowania. ", "Błąd", MessageBoxButton.OK, MessageBoxImage.Error);
                            }
                            else
                                MessageBox.Show("Ilość rund jest nieprawidłowa. ", "Błąd", MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                        else
                            MessageBox.Show("Ilość rund musi być liczbą. ", "Błąd", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                    else
                        MessageBox.Show("Plik nie jest zaszyfrowany. ", "Błąd", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                else
                    MessageBox.Show("Nie wybrano zadnego pliku. ", "Błąd", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else if (Operation == ActionType.ChangingText)
            {
                Label lblKeyValidation = ((Label)FormToValidate.FindName("lblKeyValidation"));
                Brush red = new SolidColorBrush(Color.FromArgb(0xFF, 0xE0, 0x51, 0x51));
                Brush green = new SolidColorBrush(Color.FromArgb(0xFF, 0x70, 0x8C, 0x00));

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
                                        ValidationResults = new List<object> { key, rounds };
                                        return true;
                                    }
                                    else if (key == null)
                                    {
                                        lblKeyValidation.Content = "To nie jest klucz w " + (keyMode == KeyMode.Bytes ? "bajtach oddzielonych przecinkiem" : "formacie UTF-8");
                                        lblKeyValidation.Foreground = red;
                                    }
                                    else if (key != null)
                                    {
                                        ValidationResults = new List<object> { key };
                                        return false;
                                    }
                                }
                                else
                                {
                                    lblKeyValidation.Content = "Klucz jest pusty";
                                    lblKeyValidation.Foreground = red;
                                }
                            }
                            else
                            {
                                lblKeyValidation.Content = "Nie wybrano sposobu szyfrowania";
                                lblKeyValidation.Foreground = red;
                            }
                        }
                        else
                        {
                            lblKeyValidation.Content = "Niepoprawna liczba rund";
                            lblKeyValidation.Foreground = red;
                        }
                    }
                    else
                    {
                        lblKeyValidation.Content = "Ilość rund nie jest liczbą";
                        lblKeyValidation.Foreground = red;
                    }
                }
                else
                {
                    lblKeyValidation.Content = "Nie wybrano zadnego pliku";
                    lblKeyValidation.Foreground = red;
                }
            }

            ValidationResults = null;
            return false;
        }

        private bool CheckIfModeIsValid(Control FormToValidate)
        {
            RadioButton rbBitSliceMode = ((RadioButton)FormToValidate.FindName("rbBitSliceMode"));
            RadioButton rbStandardMode = ((RadioButton)FormToValidate.FindName("rbStandardMode"));

            return rbBitSliceMode.IsChecked != rbStandardMode.IsChecked;
        }

        private bool CheckIfRoundsAreValid(int rounds)
        {
            return rounds <= 64 && rounds > 0;
        }

        private bool CheckIfRoundsAreParsable(Control FormToValidate, out int Rounds)
        {
            TextBox txtRounds = ((TextBox)FormToValidate.FindName("txtRounds"));
            Regex rgxPattern = new Regex("^[0-9]+$");

            return
                int.TryParse(txtRounds.Text, out Rounds) && rgxPattern.IsMatch(txtRounds.Text);
        }

        private bool CheckIfExtensionIsProvided(Control FormToValidate)
        {
            return
                !string.IsNullOrEmpty(((TextBox)FormToValidate.FindName("txtDecryptedFileExtension")).Text) &&
                ((TextBox)FormToValidate.FindName("txtDecryptedFileExtension")).Text != "...";
        }

        private bool CheckIfFileHasBeenChosen(Control FormToValidate)
        {
            return
                !string.IsNullOrEmpty(((TextBox)FormToValidate.FindName("txtSourceFile")).Text) &&
                ((TextBox)FormToValidate.FindName("txtSourceFile")).Text != "Wybierz lub przeciągnij plik...";
        }

        private bool CheckIfFileIsNotEncryptedAlready(Control FormToValidate)
        {
            return
                System.IO.Path.GetExtension(((TextBox)FormToValidate.FindName("txtSourceFile")).Text.ToLower()) != ".serpent";
        }

        private bool CheckIfFileIsNotDecryptedAlready(Control FormToValidate)
        {
            return
                System.IO.Path.GetExtension(((TextBox)FormToValidate.FindName("txtSourceFile")).Text.ToLower()) == ".serpent";
        }

        private bool CheckIfKeyIsValid(string StrKey, KeyMode KeyMode, out byte[] Key)
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
                List<byte> listKeyBytes = new List<byte>();
                StringBuilder sb = new StringBuilder();
                int num = -1;

                for (int i = 0; i <= StrKey.Length; i++)
                {
                    if (i < StrKey.Length && int.TryParse(StrKey[i].ToString(), out num))
                        sb.Append(num);
                    else if (sb.Length > 0) // jeśli na końcu jest przecinek to trzeba też sprawdzić czy sb coś zawiera, żeby nie próbowało sparsować czegoś pustego
                    {
                        num = int.Parse(sb.ToString());

                        if (num <= byte.MaxValue && (i == StrKey.Length || StrKey[i] == ',')) // indeks wykroczy poza tablicę, alepętla przechodzi jeszcze raz tylko po to, żeby sparsować ostatnią wartość, najpierw sprawdzam warunek długości, bo drugiego warunku nigdy nie sprawdzi przy ostatnim przejściu i nie wyrzuci błędu
                        {
                            listKeyBytes.Add((byte)num);
                            sb.Clear();
                        }
                        else
                            return false;
                    }
                    else if (i == StrKey.Length && StrKey[i - 1] == ',' && listKeyBytes.Count > 0)
                        break;
                    else
                        return false;
                }

                Key = listKeyBytes.ToArray();
            }
            else
                return false;

            return
                (Key.Length % 4) == 0 && (Key.Length / 4) <= 8;
        }

        private byte[] ParseBytesFromKeyString(string strKeyInBytes)
        {
            List<byte> listKeyBytes = new List<byte>();
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < strKeyInBytes.Length; i++)
            {
                int num;

                if (int.TryParse(strKeyInBytes[i].ToString(), out num))
                    sb.Append(num);
                else
                {
                    listKeyBytes.Add(byte.Parse(sb.ToString()));
                    sb.Clear();
                }
            }

            return listKeyBytes.ToArray();
        }

        public bool CheckIfKeyIsEmpty(Control FormToValidate)
        {
            TextBox txtKey = ((TextBox)FormToValidate.FindName("txtKey"));

            return
                string.IsNullOrEmpty(txtKey.Text) || txtKey.Text == "klucz...";
        }

        public string GetKeyString(byte[] key, KeyMode keyMode)
        {
            StringBuilder sb = new StringBuilder();

            if (keyMode == KeyMode.Bytes)
            {
                foreach (byte b in key)
                    sb.Append(b.ToString() + ", ");

                return sb.ToString().Remove(sb.ToString().Length - 2);
            }
            else if (keyMode == KeyMode.Chars)
            {
                string avlChars = "aąbcćdeęfghijklmnoópqrstuvwxyzżźAĄBCĆDEĘFGHIJKLMNOÓPQRSTUVWXYZŻŹ~!@#$%^&*()-_=+,./;\'[]<>?:\"|\\{}";
                UTF8Encoding enc = new UTF8Encoding();
                int b = 0;

                while (enc.GetByteCount(sb.ToString()) != key.Length)
                {
                    sb.Append(avlChars[key[b++ % key.Length] % avlChars.Length]);

                    while (enc.GetByteCount(sb.ToString()) > key.Length)
                        sb.Length--;
                }

                return sb.ToString();
            }
            else
                throw new Exception("Niepoprawny sposób wprowadzania klucza. ");
        }

        public bool CheckIfRoundsNumIsEmpty(Control FormToValidate)
        {
            TextBox txtRounds = ((TextBox)FormToValidate.FindName("txtRounds"));

            return
                string.IsNullOrEmpty(txtRounds.Text) || txtRounds.Text == "rundy...";
        }

        public string GetWordEnding(int n)
        {
            string strN = n.ToString();

            if (strN.EndsWith("2") || strN.EndsWith("3") || strN.EndsWith("4"))
                return "y";
            else if (strN == "1")
                return string.Empty;
            else
                return "ów";
        }
    }
}
