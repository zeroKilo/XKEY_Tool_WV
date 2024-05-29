using Be.Windows.Forms;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace XKEY_Tool_WV
{
    public partial class Form1 : Form
    {
        public byte[] dataInput, dataOutput;
        public Dictionary<string, byte[]> aesKeys = new Dictionary<string, byte[]>();
        public Dictionary<string, byte[]> aesIVs = new Dictionary<string, byte[]>();
        public Form1()
        {
            InitializeComponent();
            if(!File.Exists("keys.csv"))
            {
                MessageBox.Show("Error: keys.csv is missing!");
                Close();
                return;
            }
            string[] lines = File.ReadAllLines("keys.csv");
            foreach(string line in lines)
            {
                string[] parts = line.Split(';');
                if (parts.Length != 3)
                    continue;
                string type = parts[0];
                string name = Convert.ToBase64String(Encoding.UTF8.GetBytes(parts[1]));
                string hex = parts[2].Trim().Replace(" ", "");
                byte[] data = Helper.StringToByteArray(hex);
                if (type == "IV")
                    aesIVs.Add(name, data);
                else if (type == "KEY")
                    aesKeys.Add(name, data);
            }
        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            int n = comboBox1.SelectedIndex;
            comboBox2.Items.Clear();
            foreach (KeyValuePair<string, byte[]> pair in aesKeys)
                comboBox2.Items.Add(Helper.PrintKeyOrIV(pair));
            comboBox2.SelectedIndex = 0;
            comboBox3.Items.Clear();
            switch (n)
            {
                case 0:
                case 1:
                    comboBox3.Items.Add(Helper.PrintKeyOrIV(aesIVs.ElementAt(0)));
                    comboBox3.SelectedIndex = 0;
                    comboBox3.Enabled = false;
                    break;
                case 2:
                    foreach (KeyValuePair<string, byte[]> pair in aesIVs)
                        comboBox3.Items.Add(Helper.PrintKeyOrIV(pair));
                    comboBox3.SelectedIndex = 0;
                    comboBox3.Enabled = true;
                    break;
            }
            
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            comboBox1.SelectedIndex = 0;
        }

        private void openInputToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFileDialog d = new OpenFileDialog();
            d.Filter = "*.*|*.*";
            if (d.ShowDialog() == DialogResult.OK)
            {
                dataInput = File.ReadAllBytes(d.FileName);
                hb1.ByteProvider = new DynamicByteProvider(dataInput);
                Log("Loaded " + dataInput.Length + " bytes as input from " + d.FileName);
            }
        }

        private void saveOutputToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if(dataOutput == null || dataOutput.Length == 0)
            {
                MessageBox.Show("No data to save!");
                return;
            }
            SaveFileDialog d = new SaveFileDialog();
            d.Filter = "*.*|*.*";
            if (d.ShowDialog() == DialogResult.OK)
            {
                File.WriteAllBytes(d.FileName, dataOutput);
                Log("Written " + dataOutput.Length + " bytes as output to " + d.FileName);
            }
        }

        private void decryptToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if(dataInput == null || dataInput.Length == 0)
            {
                MessageBox.Show("Please load input file!");
                return;
            }
            Log("Selected Action: Decrypt");
            int type = comboBox1.SelectedIndex;
            byte[] key = new MemoryStream(aesKeys.ElementAt(comboBox2.SelectedIndex).Value).ToArray();
            byte[] iv = new MemoryStream(aesIVs.ElementAt(comboBox3.SelectedIndex).Value).ToArray();
            byte[] data = new MemoryStream(dataInput).ToArray();
            int count = data.Length / 0x200;
            if (data.Length % 0x200 != 0)
                count++;
            Log(count + " Blocks to decrypt");
            Log("ByteSwap16 on Data");
            Helper.ByteSwap16(data);
            Log("ByteSwap4 on Key");
            Helper.ByteSwap4(key);
            if(type == 2)
            {
                Log("ByteSwap16 on IV");
                Helper.ByteSwap16(iv);
            }
            Log("Key used: " + Helper.ByteArrayToHex(key));
            Log("IV used: " + Helper.ByteArrayToHex(iv));
            Log("Decrypting...");
            Aes aes = Helper.GetAes(key, iv);
            dataOutput = CryptTransform(aes, data, true, type == 2);
            Log("ByteSwap16 on Data");
            Helper.ByteSwap16(dataOutput);
            hb2.ByteProvider = new DynamicByteProvider(dataOutput);
            Log("Done.");
        }

        private void encryptToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (dataInput == null || dataInput.Length == 0)
            {
                MessageBox.Show("Please load input file!");
                return;
            }
            Log("Selected Action: Encrypt");
            int type = comboBox1.SelectedIndex;
            byte[] key = new MemoryStream(aesKeys.ElementAt(comboBox2.SelectedIndex).Value).ToArray();
            byte[] iv = new MemoryStream(aesIVs.ElementAt(comboBox3.SelectedIndex).Value).ToArray();
            byte[] data = new MemoryStream(dataInput).ToArray();
            int count = data.Length / 0x200;
            if (data.Length % 0x200 != 0)
                count++;
            Log(count + " Blocks to encrypt");
            if (updateKernelChecksumsToolStripMenuItem.Checked)
            {
                byte[] crcHeader, crcData;
                Log("Fixing Kernel Image Checksums...");
                Helper.FixHeaderChecksums(data, out crcHeader, out crcData);
                Log("New Header CRC32: " + Helper.ByteArrayToHex(crcHeader));
                Log("New Data CRC32: " + Helper.ByteArrayToHex(crcData));
            }
            Log("ByteSwap16 on Data");
            Helper.ByteSwap16(data);
            Log("ByteSwap4 on Key");
            Helper.ByteSwap4(key);
            if (type == 2)
            {
                Log("ByteSwap16 on IV");
                Helper.ByteSwap16(iv);
            }
            Log("Key used: " + Helper.ByteArrayToHex(key));
            Log("IV used: " + Helper.ByteArrayToHex(iv));
            Log("Encrypting...");
            Aes aes = Helper.GetAes(key, iv);
            dataOutput = CryptTransform(aes, data, false, type == 2);
            Log("ByteSwap16 on Data");
            Helper.ByteSwap16(dataOutput);
            hb2.ByteProvider = new DynamicByteProvider(dataOutput);
            Log("Done.");
        }

        public byte[] CryptTransform(Aes aes, byte[] data, bool decrypt, bool isKernel)
        {
            byte[] result = new byte[data.Length];
            int count = data.Length / 0x200;
            if (data.Length % 0x200 != 0)
                count++;
            var decryptor = aes.CreateDecryptor();
            var encryptor = aes.CreateEncryptor();
            MemoryStream m = new MemoryStream(data);
            pb1.Minimum = 0;
            pb1.Maximum = count;
            for (int i = 0; i < count; i++)
            {
                pb1.Value = i;
                if (i % 100 == 0)
                    Application.DoEvents();
                byte[] block = new byte[512];
                if (m.Position + 0x200 < m.Length)
                    m.Read(block, 0, 0x200);
                else
                    m.Read(block, 0, (int)(m.Length - m.Position));
                if (!isKernel)
                {
                    byte[] patch = BitConverter.GetBytes(i);
                    byte[] iv = aes.IV;
                    for (int j = 0; j < 4; j++)
                        iv[12 + j] = patch[3 - j];
                    decryptor = aes.CreateDecryptor();
                    encryptor = aes.CreateEncryptor();
                }
                int remaining = data.Length - i * 0x200;
                if (remaining > 0x200)
                    remaining = 0x200;
                if (decrypt)
                {
                    CryptoStream cryptStream = new CryptoStream(new MemoryStream(block), decryptor, CryptoStreamMode.Read);
                    cryptStream.Read(result, i * 0x200, remaining);
                }
                else
                {
                    MemoryStream encrypted = new MemoryStream();
                    CryptoStream cryptStream = new CryptoStream(encrypted, encryptor, CryptoStreamMode.Write);
                    cryptStream.Write(block, 0, remaining);
                    byte[] buff = encrypted.ToArray();
                    for (int j = 0; j < remaining; j++)
                        result[i * 0x200 + j] = buff[j];
                }
            }
            pb1.Value = 0;
            return result;
        }

        private void Log(string s)
        {
            rtb1.Text += s + "\n";
            rtb1.SelectionStart = rtb1.Text.Length;
            rtb1.ScrollToCaret();
        }
    }
}
