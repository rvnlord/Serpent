using System.Collections.Generic;
using System.IO;

namespace WPFSerpent.Source.Models
{
    public class FileManagement
    {
        public void ShiftBytesFromFile(string InputFilePath, string TempFilePath, int Offset, out ErrorCode Code)
        {
            try
            {
                if (File.Exists(TempFilePath))
                    File.Delete(TempFilePath);

                using (var fsNewFile = new FileStream(TempFilePath, FileMode.CreateNew, FileAccess.Write))
                {
                    using (var fsOldFile = new FileStream(InputFilePath, FileMode.Open, FileAccess.Read))
                    {
                        fsOldFile.Seek(Offset, SeekOrigin.Begin);
                        fsOldFile.CopyTo(fsNewFile);
                    }

                    Code = ErrorCode.Ok;
                }
            }
            catch // w razie błędu zwracam odpowiedni kod
            {
                Code = ErrorCode.ShiftFileFailed;
            }
        }

        public void UnshiftBytesToFile(string InputFilePath, string TempFilePath, byte[] Bytes, out ErrorCode Code)
        {
            try
            {
                if (File.Exists(TempFilePath))
                    File.Delete(TempFilePath);

                using (var fsNewFile = new FileStream(TempFilePath, FileMode.CreateNew, FileAccess.Write))
                {
                    fsNewFile.Write(Bytes, 0, Bytes.Length);

                    using (var fsOldFile = new FileStream(InputFilePath, FileMode.Open, FileAccess.Read))
                    {
                        fsOldFile.CopyTo(fsNewFile);
                    }

                    Code = ErrorCode.Ok;
                }
            }
            catch // w razie błędu zwracam odpowiedni kod
            {
                Code = ErrorCode.ExpandFileFailed;
            }
        }

        public void DeleteTempFile(string TempFilePath, out ErrorCode Code)
        {
            try
            {
                if (File.Exists(TempFilePath))
                    File.Delete(TempFilePath);

                Code = ErrorCode.Ok;
            }
            catch // w razie błędu zwracam odpowiedni kod
            {
                Code = ErrorCode.DeletingTempFileFailed;
            }
        }

        public byte[] GetFileFragment(string InputFilePath, long Offset, long Count, out ErrorCode Code)
        {
            try
            {
                SetFileReadable(InputFilePath);

                using (var fsInput = new FileStream(InputFilePath, FileMode.Open)) // tworzę strumień czytający plik
                {
                    var listBytes = new List<byte>();
                    int currByte;

                    fsInput.Seek(Offset, SeekOrigin.Begin); // ustalam początek zczytywania danych

                    while ((currByte = fsInput.ReadByte()) != -1 && listBytes.Count < Count) // czytam plik po bajcie dopóki się nie skończy, chyba, że program wczyta maksymalną długość fragmentu
                        listBytes.Add((byte) currByte); // dodaję bajty do listy

                    Code = ErrorCode.Ok;

                    fsInput.Dispose();
                    fsInput.Close();
                    return listBytes.ToArray(); // zwracam tablicę bajtów
                }
            }
            catch // w razie błędu zwracam odpowiedni kod
            {
                Code = ErrorCode.GetFileFailed;
                return new byte[1];
            }
        }

        public void SaveFileFragment(string SaveFilePath, long Offset, byte[] OutputFileFragment, out ErrorCode Code)
        {
            try
            {
                if (Offset == 0) // usuwam plik jeżeli program zaczyna czytać początek pliku, ale plik o takiej samej nazwie już istnieje
                    if (File.Exists(SaveFilePath))
                        File.Delete(SaveFilePath);

                using (var fsOutput = new FileStream(SaveFilePath, FileMode.Append)) // otwieram strumień zapisujący plik
                {
                    fsOutput.Write(OutputFileFragment, 0, OutputFileFragment.Length); // zapisuję bajty w pliku docelowym

                    fsOutput.Dispose();
                    fsOutput.Close();
                    Code = ErrorCode.Ok;
                }
            }
            catch // w razie błędu zwracam odpowiedni kod
            {
                Code = ErrorCode.SaveFileFailed;

                if (File.Exists(SaveFilePath))
                    File.Delete(SaveFilePath);
            }
        }

        private static void SetFileReadable(string InputFilePath)
        {
            var attributes = File.GetAttributes(InputFilePath);

            if ((attributes & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
            {
                attributes = RemoveAttribute(attributes, FileAttributes.ReadOnly);
                File.SetAttributes(InputFilePath, attributes);
            }
        }

        private static FileAttributes RemoveAttribute(FileAttributes attributes, FileAttributes attributesToRemove)
        {
            return attributes & ~attributesToRemove;
        }
    }

    public enum ErrorCode
    {
        SaveFileFailed,
        GetFileFailed,
        ReadingSigneturesFromXmlFailed,
        XmlFileDoesNotExist,
        Ok,
        DeletingTempFileFailed,
        ExpandFileFailed,
        ShiftFileFailed
    }
}
