using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
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

namespace DiffieHellman
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {

        static CngKey aKey;
        static CngKey bKey;
        static byte[] aPubKeyBlob;
        static byte[] bPubKeyBlob;

        byte[] encryptedData;
        public MainWindow()
        {
            InitializeComponent();
        }
        private static void CreateKeys()

        {

            aKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);

            bKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);

            aPubKeyBlob = aKey.Export(CngKeyBlobFormat.EccPublicBlob);

            bPubKeyBlob = bKey.Export(CngKeyBlobFormat.EccPublicBlob);

        }

private void button1_Click(object sender, EventArgs e)

        {

            CreateKeys();

            textBox1.Text = Convert.ToBase64String(aPubKeyBlob);

            textBox2.Text = Convert.ToBase64String(bPubKeyBlob);

        }

private void button2_Click(object sender, EventArgs e)

        {

            // Шифруемое сообщение

            string message = textBox3.Text;

            // Преобразование строки шифруемого текста в

            // массив байтов

            byte[] rawData = Encoding.UTF8.GetBytes(message);

            encryptedData = null;

            // Создание объекта ECDiffieHellmanCng и

            // инициализация его с помощью ключей

            // пользователя А

            ECDiffieHellmanCng aAlgorithm = new ECDiffieHellmanCng(aKey);

            using (CngKey bPubKey = CngKey.Import(bPubKeyBlob, CngKeyBlobFormat.EccPublicBlob))

            {

                // Пользователь А создает симметричный ключ

                // путем импользования своей пары ключей и

                // открытого ключа пользователя В, вызывая

                // метод DeriveKeyMaterial()

                byte[] symmKey = aAlgorithm.DeriveKeyMaterial(bPubKey);

                textBox4.Text = Convert.ToBase64String(symmKey);

                // Созданный симметричный ключ используется с

                // алгоритмом AES для шифрования сообщения,

                // передаваемого пользователю В

                AesCryptoServiceProvider aes = new AesCryptoServiceProvider();

                aes.Key = symmKey;

                // Динамическая генерация начального вектора IV

                aes.GenerateIV();

                using (ICryptoTransform encryptor = aes.CreateEncryptor())

                using (MemoryStream ms = new MemoryStream())

                {

                    // создается CryptoStream и шифруются

                    // подлежащие отправке данные

                    CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);

                    // Записывается вектор инициализации IV

                    //не шифруя

                    ms.Write(aes.IV, 0, aes.IV.Length);

                    cs.Write(rawData, 0, rawData.Length);

                    cs.Close();

                    encryptedData = ms.ToArray();

                    textBox5.Text = Convert.ToBase64String(encryptedData);

                }

                aes.Clear();

            }

        }

private void button3_Click(object sender, EventArgs e)

        {

            textBox6.Text = Convert.ToBase64String(encryptedData);

            byte[] rawData = null;

            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();

            // Свойство BlockSize класса

            // AesCryptoServiceProvider возвращает количество

            // битов в полученном блоке.

            // Количество байтов получается делением на 8

            int nBytes = aes.BlockSize >> 3;

            // Извлекается вектор инициализации

            byte[] iv = new byte[nBytes];

            for (int i = 0; i < iv.Length; i++)

                iv[i] = encryptedData[i];

            // Создание объекта ECDiffieHellmanCng и

            // инициализация его с помощью ключей

            // пользователя В
            ECDiffieHellmanCng bAlgorithm = new ECDiffieHellmanCng(bKey);

            using (CngKey aPubKey = CngKey.Import(aPubKeyBlob, CngKeyBlobFormat.EccPublicBlob))

            {

                // Пользователь В создает симметричный ключ

                // путем импользования своей пары ключей и

                // открытого ключа пользователя А, вызывая

                // метод DeriveKeyMaterial()

                byte[] symmKey = bAlgorithm.DeriveKeyMaterial(aPubKey);

                textBox7.Text = Convert.ToBase64String(symmKey);

                aes.Key = symmKey;

                aes.IV = iv;

                // Дешифрование полученного сообщения с помощью

                // симметричного ключа symmKey

                using (ICryptoTransform decryptor = aes.CreateDecryptor())

                using (MemoryStream ms = new MemoryStream())

                {

                    CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write);

                    cs.Write(encryptedData, nBytes, encryptedData.Length - nBytes);

                    cs.Close();

                    rawData = ms.ToArray();

                    textBox8.Text = Encoding.UTF8.GetString(rawData);

                }

            }

            aes.Clear();

        }
    }
}
