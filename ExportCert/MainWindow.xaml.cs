using Microsoft.Win32;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Input;

namespace ExportCert
{
    public class CertInfo
    {
        public string Issuer { get; private set; }
        public string Subject { get; private set; }
        public DateTime NotBefore { get; private set; }
        public DateTime NotAfter { get; private set; }
        public string SerialNumber { get; private set; }
        byte[] CspBlob { get; set; }

        public CertInfo(X509Certificate2 cert)
        {
            Issuer = cert.Issuer;
            Subject = cert.Subject;
            SerialNumber = cert.SerialNumber;
            NotBefore = cert.NotBefore;
            NotAfter = cert.NotAfter;
            RSACryptoServiceProvider provider = (RSACryptoServiceProvider)cert.PrivateKey;
            CspBlob = provider.ExportCspBlob(true);
        }

        public void SaveAs(string path)
        {
            using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write))
            {
                fs.Write(CspBlob, 0, CspBlob.Length);
            }
        }
    }

    public partial class MainWindow : Window
    {
        public ObservableCollection<CertInfo> Certificates { get; set; }

        public MainWindow()
        {
            Certificates = new ObservableCollection<CertInfo>();

            InitializeComponent();

            CertList.DataContext = Certificates;

            RefreshCertificates();
        }

        private void RefreshCertificates()
        {
            var store = new X509Store(StoreLocation.CurrentUser);
            store.Open(OpenFlags.MaxAllowed);
            Certificates.Clear();
            foreach (var cert in
            store.Certificates
                .OfType<X509Certificate2>()
                .Where(cert => cert.HasPrivateKey
                    && IsSigningCertificate(cert)))
            {
                Certificates.Add(new CertInfo(cert));
            }
            store.Close();
        }

        private static bool IsSigningCertificate(X509Certificate2 cert)
        {
            bool result = cert.Extensions
                .OfType<X509KeyUsageExtension>()
                .Any(keyUsage => keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature))
                && cert.Extensions
                .OfType<X509EnhancedKeyUsageExtension>()
                .Any(extended => 
                    extended.EnhancedKeyUsages
                        .OfType<Oid>()
                        .Any(oid => string.Equals("1.3.6.1.5.5.7.3.3", oid.Value)));
            return result;
        }

        private void ExportSelectedCert()
        {
            var cert = CertList.SelectedItem as CertInfo;
            if (cert == null)
            {
                return;
            }

            SaveFileDialog save = new SaveFileDialog();
            save.AddExtension = true;
            save.CheckFileExists = false;
            save.CheckPathExists = true;
            save.DefaultExt = ".snk";
            save.Filter = "Strong Name Key Files|*.snk|All Files|*.*";
            save.FilterIndex = 1;
            save.OverwritePrompt = true;
            save.RestoreDirectory = true;
            save.Title = "Save to a Strong Name Key File...";
            save.ValidateNames = true;

            var result = save.ShowDialog(this);
            if (result == null || !result.Value)
            {
                return;
            }

            cert.SaveAs(save.FileName);
        }

        private void CertList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            ExportSelectedCert();
        }

        private void Export_Click(object sender, RoutedEventArgs e)
        {
            ExportSelectedCert();
        }
    }
}
