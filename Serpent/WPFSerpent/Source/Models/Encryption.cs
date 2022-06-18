using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace WpfSerpent.Source.Models
{
    public class SerpentCipher
    {
        private const int BlockSize = 16; // bytes in a data-block
        private const int DefaultKeySize = 32;
        private static readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        public bool Encrypt(string FilePath, byte[] Key, int Rounds, Mode Mode, EncryptionMode EncrMode)
        {
            var fm = new FileManagement();
            SerpentAlgorithm sa;
            var saltBytes = new byte[BlockSize];
            rng.GetNonZeroBytes(saltBytes);
            var iv = new byte[BlockSize];
            rng.GetBytes(iv);

            switch (Mode)
            {
                case Mode.Standard:
                    sa = new SerpentStandardMode();
                    break;
                case Mode.BitSlice:
                    sa = new SerpentBitSliceMode();
                    break;
                default:
                    MessageBox.Show("Selected algorithm type is not implemented. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return false;
            }
            
            var position = 0;
            var destFilePath = Path.ChangeExtension(FilePath, ".serpent");
            var fi = new FileInfo(FilePath);
            var fragmentSize = 1024 * 1024; // 1 MB (musi dać się wyciągnąć pierwiastek czwartego stopnia)
            var tempFilePath = FilePath + ".temp";
            var tempFilePath2 = FilePath + ".temp2";
            Encoding enc = new UTF8Encoding();
            sa.Rounds = Rounds;
            sa.BlockSize = BlockSize;
            var previousBlock = Array.Empty<byte>();

            var roundsBytes = enc.GetBytes(Rounds.ToString());

            for (var i = 0; i < roundsBytes.Length; i++)
            {
                saltBytes[i] = roundsBytes[i];

                if (i >= roundsBytes.Length - 1)
                    saltBytes[i + 1] = 3;
            }

            var expandedKey = sa.MakeKey(Key);

            var leadingBytes = new byte[BlockSize - fi.Length % BlockSize];
            rng.GetBytes(leadingBytes);
            leadingBytes[0] = (byte)leadingBytes.Length;

            fm.UnshiftBytesToFile(FilePath, tempFilePath, leadingBytes, out var errorCode); // po czym dodaję go do pliku tymczasowego

            if (errorCode == ErrorCode.ExpandFileFailed)
            {
                MessageBox.Show("File couldn't be modified.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }

            do
            {
                if (position == 0) // dodaj do pliku informację o rozszerzeniu, ilości rund i sumę kontrolną
                {
                    var infoBytes = new List<byte>();

                    infoBytes.AddRange(saltBytes);

                    var extension = Path.GetExtension(FilePath);
                    extension = extension.Replace(".", "");
                    infoBytes.AddRange(enc.GetBytes(extension));
                    infoBytes.Add(3); // EOT byte
                    infoBytes.AddRange(enc.GetBytes(Rounds.ToString()));
                    infoBytes.Add(3);

                    if (BlockSize < infoBytes.Count - saltBytes.Length)
                    {
                        MessageBox.Show("FIle extension is too long.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        return false;
                    }

                    var rndBytes = new byte[BlockSize - (infoBytes.Count - saltBytes.Length)];
                    rng.GetNonZeroBytes(rndBytes);
                    infoBytes.AddRange(rndBytes);

                    fm.UnshiftBytesToFile(tempFilePath, tempFilePath2, infoBytes.ToArray(), out errorCode);

                    if (errorCode == ErrorCode.ExpandFileFailed)
                    {
                        MessageBox.Show("File couldn't be modified.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        return false;
                    }

                    fm.DeleteTempFile(tempFilePath, out errorCode);

                    if (errorCode == ErrorCode.DeletingTempFileFailed) // w razie błędu szyfrowanie nie powiodło się
                    {
                        MessageBox.Show("Temporary file couldn't be deleted.", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return false;
                    }

                    File.Move(tempFilePath2, tempFilePath);
                }

                var InputFileFragment = fm.GetFileFragment(tempFilePath, position, fragmentSize, out errorCode).ToList();

                if (errorCode == ErrorCode.GetFileFailed)
                {
                    MessageBox.Show("File couldn't be loaded.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return false;
                }

                var OutputFileFragment = new List<byte>();

                // SZYFROWANIE BLOKU

                for (var i = 0; i < InputFileFragment.Count; i += BlockSize)
                {
                    if (EncrMode == EncryptionMode.ECB)
                    {
                        OutputFileFragment.AddRange(sa.BlockEncrypt(InputFileFragment.GetRange(i, BlockSize).ToArray(), 0, expandedKey));
                    }
                    else if (EncrMode == EncryptionMode.CBC)
                    {
                        if (position == 0 && i == 0) // inicjalizuję iv tylko raz
                            previousBlock = iv;

                        var plainText = InputFileFragment.GetRange(i, BlockSize).ToArray();
                        var currBlock = plainText.XOR(previousBlock); // do plaintextu xorujemy poprzedni zaszyfrowany blok
                        var cipherText = sa.BlockEncrypt(currBlock, 0, expandedKey);
                        OutputFileFragment.AddRange(cipherText);
                        previousBlock = cipherText;
                    }
                    else
                    {
                        MessageBox.Show("Selected ciphering type is not implemented. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        return false;
                    }
                }
                
                // =================

                fm.SaveFileFragment(destFilePath, position, OutputFileFragment.ToArray(), out errorCode); // zapisuję kolejną część pliku do pliku docelowego

                if (errorCode == ErrorCode.SaveFileFailed) // w razie błędu szyfrowanie nie powiodło się
                {
                    MessageBox.Show("File couldn't be saved. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return false;
                }

                position += fragmentSize; // ustaw pozycję kolejnego fragmentu
                var encryptionProgressChangedEventData = new EncryptionProgressChangedEventArgs(((int)((double)position / fi.Length * 100.0)), ActionType.Encryption); // inicjalizuję dane dla event handlera (obliczony postęp, typ - szyfrowanie czy deszyfrowanie)
                OnEncryptionProgressChanging(encryptionProgressChangedEventData); // wywołuję zdarzenie z utworzonymi wcześniej parametrami

            }
            while (position <= fi.Length); // pętlę powtarzam dopóki nie skończy się plik

            fm.DeleteTempFile(tempFilePath, out errorCode); // usuń plik tymczasowy

            if (errorCode == ErrorCode.DeletingTempFileFailed) // w razie błędu szyfrowanie nie powiodło się
            {
                MessageBox.Show("Temporary file couldn't be deleted.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }

            var ivAndSalt = new byte[iv.Length + saltBytes.Length];
            iv.CopyTo(ivAndSalt, 0);
            saltBytes.CopyTo(ivAndSalt, iv.Length);

            fm.UnshiftBytesToFile(destFilePath, tempFilePath, ivAndSalt, out errorCode); // suma kontrolna

            if (errorCode == ErrorCode.ExpandFileFailed)
            {
                MessageBox.Show("File couldn't be modified.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }

            fm.DeleteTempFile(destFilePath, out errorCode); // usuń plik tymczasowy

            if (errorCode == ErrorCode.DeletingTempFileFailed) // w razie błędu szyfrowanie nie powiodło się
                MessageBox.Show("Temporary file couldn't be deleted.", "Ostrzeżenie", MessageBoxButton.OK, MessageBoxImage.Warning);

            File.Move(tempFilePath, destFilePath);

            return true;
        }

        public bool Decrypt(string FilePath, byte[] Key, int Rounds, Mode Mode, EncryptionMode EncrMode)
        {
            var fm = new FileManagement();
            SerpentAlgorithm sa;

            switch (Mode)
            {
                case Mode.Standard:
                    sa = new SerpentStandardMode();
                    break;
                case Mode.BitSlice:
                    sa = new SerpentBitSliceMode();
                    break;
                default:
                    MessageBox.Show("Selected algorithm type is not implemented. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return false;
            }

            var position = 0;
            var destFilePath = string.Empty;
            var fi = new FileInfo(FilePath);
            const int fragmentSize = 1024 * 1024; // 1 MB (musi dać się wyciągnąć pierwiastek czwartego stopnia)
            Encoding enc = new UTF8Encoding();
            sa.Rounds = Rounds;
            sa.BlockSize = BlockSize;
            var tempFilePath = FilePath + ".temp";

            var iv = fm.GetFileFragment(FilePath, 0, BlockSize, out var errorCodeIv);
            var plainControlSum = fm.GetFileFragment(FilePath, BlockSize, BlockSize, out var errorCode);
            var roundBytesFromPtControlSum = Array.Empty<byte>();
            var previousBlock = Array.Empty<byte>();

            if (errorCodeIv == ErrorCode.GetFileFailed || errorCode == ErrorCode.GetFileFailed)
            {
                MessageBox.Show("File couldn't be loaded.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }

            var listRoundsBytesFromPtControlSum = new List<byte>();

            for (var i = 0; i < BlockSize; i++)
            {
                if (plainControlSum[i] != 3)
                    listRoundsBytesFromPtControlSum.Add(plainControlSum[i]);
                else
                {
                    roundBytesFromPtControlSum = listRoundsBytesFromPtControlSum.ToArray();
                    break;
                }
            }
            
            var areRoundsFromPtControlSumParsable = int.TryParse(enc.GetString(roundBytesFromPtControlSum), out var readRoundsFromPtControlSum);

            if (!areRoundsFromPtControlSumParsable || readRoundsFromPtControlSum > 64)
            {
                MessageBox.Show("File isn't encrypted or it was encrypted with different algorithm.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }

            if (readRoundsFromPtControlSum != Rounds)
            {
                if (Mode != Mode.Standard)
                {
                    var result = MessageBox.Show(string.Format("File was encrypted with different number of rounds ({0}) of Serpent algorithm than the one specified ({1}) and in algorithm type different than `Standard` it is impossible to decrypt by using this number of rounds. Do you want to change alogorithm type to 'Standard' and number of rounds to {0}? (WARNING: Decryption may take a long time for big files). ", readRoundsFromPtControlSum, Rounds), "Warning", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                    return result == MessageBoxResult.Yes && Decrypt(FilePath, Key, readRoundsFromPtControlSum, Mode.Standard, EncrMode);
                }
                else
                {
                    var result = MessageBox.Show(string.Format("It looks like the file was encrypted with different number of rounds ({0}) of Serpent algorithm than the one specified ({1}) or file is not encrypted at all. Do you want to change the number of rounds to {0}?", readRoundsFromPtControlSum, Rounds), "Warning", MessageBoxButton.YesNo, MessageBoxImage.Question);

                    if (result == MessageBoxResult.Yes)
                    {
                        Rounds = readRoundsFromPtControlSum;
                        sa.Rounds = readRoundsFromPtControlSum;
                    }
                }
            }
            
            var expandedKey = sa.MakeKey(Key);

            fm.ShiftBytesFromFile(FilePath, tempFilePath, BlockSize * 2, out errorCode); // usuń z pliku dwa bloki - sumę kontrolną i initalization vector

            if (errorCode == ErrorCode.ShiftFileFailed)
            {
                MessageBox.Show("File couldn't be modified.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }

            do
            {
                var InputFileFragment = fm.GetFileFragment(tempFilePath, position, fragmentSize, out errorCode).ToList();

                if (errorCode == ErrorCode.GetFileFailed)
                {
                    MessageBox.Show("File couldn't be loaded'.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return false;
                }

                var OutputFileFragment = new List<byte>();

                // DESZYFROWANIE BLOKU

                for (var i = 0; i < InputFileFragment.Count; i += BlockSize)
                {
                    switch (EncrMode)
                    {
                        case EncryptionMode.ECB:
                            OutputFileFragment.AddRange(sa.BlockDecrypt(InputFileFragment.GetRange(i, BlockSize).ToArray(), 0, expandedKey));
                            break;
                        case EncryptionMode.CBC:
                        {
                            if (position == 0 && i == 0)
                                previousBlock = iv;
                            var cipherText = InputFileFragment.GetRange(i, BlockSize).ToArray();
                            var currBlock = sa.BlockDecrypt(cipherText, 0, expandedKey);
                            var plainText = currBlock.XOR(previousBlock);
                            OutputFileFragment.AddRange(plainText);
                            previousBlock = cipherText;
                            break;
                        }
                        default:
                            MessageBox.Show("Selected ciphering type is not implemented. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                            return false;
                    }
                }

                // ===================

                if (position == 0) // jeśli odszyfrowałem pierwszy fragment pliku, przed zapisaniem usuwam z tablicy bajty dodane przy szyfrowaniu
                {
                    int shiftedbytes = OutputFileFragment[BlockSize * 2]; // zawartość 32 bajtu, 0 - 15 deszyfrowana suma kontrolna, 16-31 rozszerzenie i ilość rund
                    var decryptedControlSum = new byte[BlockSize];
                    var extBytes = new byte[1];
                    var roundBytes = new byte[1];
                    var i = 0;

                    for (; i < BlockSize; i++) // zczytaj sumę kontrolną
                        decryptedControlSum[i] = OutputFileFragment[i];

                    var listExtbytes = new List<byte>();

                    for (; i < BlockSize * 2; i++) // zczytaj rozszerzenie
                    {
                        if (OutputFileFragment[i] != 3)
                            listExtbytes.Add(OutputFileFragment[i]);
                        else
                        {
                            extBytes = listExtbytes.ToArray();
                            break;
                        }
                    }

                    i++;
                    var listRoundsBytes = new List<byte>();

                    for (; i < BlockSize * 2; i++)  // zczytaj zaszyfrowaną ilość rund
                    {
                        if (OutputFileFragment[i] != 3)
                            listRoundsBytes.Add(OutputFileFragment[i]);
                        else
                        {
                            roundBytes = listRoundsBytes.ToArray();
                            break;
                        }
                    }

                    var outputExtension = enc.GetString(extBytes);
                    destFilePath = Path.ChangeExtension(FilePath, outputExtension);
                    var areRoundsParsable = int.TryParse(enc.GetString(roundBytes), out var readRounds);

                    if (!plainControlSum.SequenceEqual(decryptedControlSum) || !areRoundsParsable || shiftedbytes > 16 || readRounds != Rounds)
                    {
                        fm.DeleteTempFile(tempFilePath, out errorCode);
                        if (errorCode == ErrorCode.DeletingTempFileFailed)
                            MessageBox.Show("Temporary file couldn't be deleted", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);

                        MessageBox.Show("Key is invalid.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);

                        return false;
                    }

                    var shiftedBytesAndInfoBytes = shiftedbytes + BlockSize * 2;

                    for (; shiftedBytesAndInfoBytes > 0; shiftedBytesAndInfoBytes--)
                        OutputFileFragment.RemoveAt(0);
                }

                fm.SaveFileFragment(destFilePath, position, OutputFileFragment.ToArray(), out errorCode); // zapisuję kolejną część pliku do pliku docelowego

                if (errorCode == ErrorCode.SaveFileFailed) // w razie błędu szyfrowanie nie powiodło się
                {
                    MessageBox.Show("FIle couldn't be saved. ", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return false;
                }

                position += fragmentSize; // ustaw pozycję kolejnego fragmentu
                var encryptionProgressChangedEventData = new EncryptionProgressChangedEventArgs((int)((double)position / fi.Length * 100.0), ActionType.Decryption); // inicjalizuję dane dla event handlera (obliczony postęp, typ - szyfrowanie czy deszyfrowanie)
                OnEncryptionProgressChanging(encryptionProgressChangedEventData); // wywołuję zdarzenie z utworzonymi wcześniej parametrami

            }
            while (position <= fi.Length); // pętlę powtarzam dopóki nie skończy się plik

            fm.DeleteTempFile(tempFilePath, out errorCode); // usuń plik tymczasowy

            if (errorCode == ErrorCode.DeletingTempFileFailed)
                MessageBox.Show("Temporary file couldn't be deleted.", "Ostrzeżenie", MessageBoxButton.OK, MessageBoxImage.Warning);

            return true;
        }

       

        public static byte[] RandomizeKey() // Losowanie kluczy
        {
            var key = new byte[DefaultKeySize];
            rng.GetNonZeroBytes(key);
            return key;
        }

        public event EncryptionProgressChangedEventHandler EncryptionProgressChanged; // tworzę zdarzenie wywoływane przy zmianie stanu operacji szyfrowania

        protected virtual void OnEncryptionProgressChanging(EncryptionProgressChangedEventArgs e) // metoda upewniająca się, że parametry przyjmowane przez zdarzenie nie są puste
        {
            EncryptionProgressChanged?.Invoke(this, e);
        }
    }

    public enum ActionType
    {
        Encryption,
        Decryption,
        ChangingText,
    }

    public enum Mode
    {
        Standard,
        BitSlice
    }

    public enum EncryptionMode
    {
        ECB,
        CBC
    }

    public enum KeyMode
    {
        Chars,
        Bytes
    }

    public class EncryptionProgressChangedEventArgs : EventArgs // klasa danych dla zdarzenia wywoływanego pprzy zmianie statusu szyfrowania bądź deszyfrowania
    {
        public int Progress { get; } // deklaruję właściwości jednokierunkowe
        public ActionType ActionType { get; }

        public EncryptionProgressChangedEventArgs(int progress, ActionType actionType) // konstruktor
        {
            Progress = progress;
            ActionType = actionType;
        }
    }

    public delegate void EncryptionProgressChangedEventHandler(object sender, EncryptionProgressChangedEventArgs e); // deklaruję delegat zarządzający zdarzeniem wywoływanym przy zmianie stanu operacji szyfrowania lub deszyfrowania

    public static class ExtensionMethods
    {
        public static byte[] XOR(this byte[] buffer1, byte[] buffer2)
        {
            for (var i = 0; i < buffer1.Length; i++)
                buffer1[i] ^= buffer2[i];

            return buffer1;
        }
    }
}
