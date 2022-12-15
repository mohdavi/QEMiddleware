using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Configuration;
using System.Data.SqlClient;
using System.IO;
using System.Timers;
using System.Xml;
using static System.Net.Mime.MediaTypeNames;
using System.Runtime.InteropServices;  // DllImport
using System.Security.Principal; // WindowsImpersonationContext

namespace WindowsService1
{
    public enum SECURITY_IMPERSONATION_LEVEL : int
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3
    }
    public partial class Service1 : ServiceBase
    {
        Timer timer = new Timer(); // name space(using System.Timers;)
                                   // obtains user token
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LogonUser(string pszUsername, string pszDomain, string pszPassword,
            int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        // closes open handes returned by LogonUser
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public extern static bool CloseHandle(IntPtr handle);

        // creates duplicate token handle
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.Security.Principal.WindowsImpersonationContext newUser1;
        private System.Security.Principal.WindowsImpersonationContext newUser2;
        public Service1()
        {
            InitializeComponent();

        }

        protected override void OnStart(string[] args)
        {
            WriteToFile("Data Transfer Service is started at " + DateTime.Now);
            timer.Elapsed += new ElapsedEventHandler(OnElapsedTime);
            timer.Interval = 60000; //number in milisecinds
            timer.Enabled = true;
            Datacopy();
        }

        protected override void OnStop()
        {
            WriteToFile("Data Transfer Service is stopped at " + DateTime.Now);
        }

        private void OnElapsedTime(object source, ElapsedEventArgs e)
        {
            Datacopy();
        }

        public void WriteToFile(string Message)
        {
            string path = AppDomain.CurrentDomain.BaseDirectory + "\\Logs";
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }
            string filepath = AppDomain.CurrentDomain.BaseDirectory + "\\Logs\\ServiceLog_" + DateTime.Now.Date.ToShortDateString().Replace('/', '_') + ".txt";
            if (!File.Exists(filepath))
            {
                // Create a file to write to. 
                using (StreamWriter sw = File.CreateText(filepath))
                {
                    sw.WriteLine(Message);
                }
            }
            else
            {
                using (StreamWriter sw = File.AppendText(filepath))
                {
                    sw.WriteLine(Message);
                }
            }
        }

        public void Datacopy()
        {
            //TimeSpan start = new TimeSpan(0, 0, 0); //Midnight
            //TimeSpan end = new TimeSpan(1, 0, 0); //1 AM
            //TimeSpan now = DateTime.Now.TimeOfDay;

            //if ((now > start) && (now < end))
            //{

            WriteToFile("Data Copy Process is starting now...");

            string sourceCS = string.Empty;
            string destinationCS = string.Empty;
            string DomainName = String.Empty;
            string WinUserName1 = string.Empty;
            string WinUserPass1 = string.Empty;
            string WinUserName2 = string.Empty;
            string WinUserPass2 = string.Empty;

            try
            {
                using (XmlReader reader = XmlReader.Create(AppDomain.CurrentDomain.BaseDirectory + @"\ServerConn.xml"))
                {
                    while (reader.Read())
                    {
                        if (reader.IsStartElement())
                        {
                            //return only when you have START tag  
                            switch (reader.Name.ToString())
                            {
                                case "Source":
                                    sourceCS = reader.ReadString();
                                    break;
                                case "Destination":
                                    destinationCS = reader.ReadString();
                                    break;
                                case "Domain":
                                    DomainName = reader.ReadString();
                                    break;
                                case "WinUserName1":
                                    WinUserName1 = reader.ReadString();
                                    break;
                                case "WinUserPass1":
                                    WinUserPass1 = reader.ReadString();
                                    break;
                                case "WinUserName2":
                                    WinUserName2 = reader.ReadString();
                                    break;
                                case "WinUserPass2":
                                    WinUserPass2 = reader.ReadString();
                                    break;
                            }
                        }
                    }
                }

                // attempt to impersonate user 1
                WriteToFile("Now attempting to impersonate user 1...");
                newUser1 = this.ImpersonateUser(WinUserName1, DomainName, WinUserPass1);

                WriteToFile("User 1 Impersonated Successfully. Now initiating connection of Source Server...");
                using (SqlConnection sourceCon = new SqlConnection(sourceCS))
                {
                    SqlCommand cmd0 = new SqlCommand("Select * from MPS_CARDS", sourceCon);

                    sourceCon.Open();
                    WriteToFile("Source Server Connection successful...");

                    using (SqlDataReader rdr = cmd0.ExecuteReader())
                    {
                        DataTable dt0 = new DataTable();
                        dt0.Load(rdr);

                        // attempt to impersonate user 2
                        WriteToFile("Now attempting to impersonate user 2...");
                        newUser2 = this.ImpersonateUser(WinUserName2, DomainName, WinUserPass2);

                        WriteToFile("User 2 Impersonated Successfully. Now initiating connection of Destination Server...");
                        using (SqlConnection destinationCon = new SqlConnection(destinationCS))
                        {
                            SqlCommand cmd2 = new SqlCommand("Select * from MPS_CARDS", destinationCon);
                            using (SqlBulkCopy bc = new SqlBulkCopy(destinationCon))
                            {
                                bc.DestinationTableName = "MPS_CARDS";
                                destinationCon.Open();

                                WriteToFile("Destination Server Connection successful...");
                                DataTable dtFirstTable = dt0;
                                DataTable dtSecondTable = new DataTable();
                                SqlDataReader rdr2 = cmd2.ExecuteReader();
                                dtSecondTable.Load(rdr2);

                                //dtThirdTable is the table which will hold unmatched rows of dtFirstTable and dtSecondTable
                                DataTable dtThirdTable = new DataTable();

                                dtThirdTable.Columns.Add("CARD_NO", Type.GetType("System.String"));
                                dtThirdTable.Columns.Add("QP_STAFF_NUMBER", Type.GetType("System.String"));
                                dtThirdTable.Columns.Add("LOCATION", Type.GetType("System.String"));

                                foreach (DataRow drFirstTableRow in dtFirstTable.Rows)
                                {
                                    bool matched = false;
                                    foreach (DataRow drSecondTableRow in dtSecondTable.Rows)
                                    {
                                        if (drFirstTableRow["CARD_NO"].ToString() == drSecondTableRow["CARD_NO"].ToString() && drFirstTableRow["QP_STAFF_NUMBER"].ToString() == drSecondTableRow["QP_STAFF_NUMBER"].ToString() && drFirstTableRow["LOCATION"].ToString() == drSecondTableRow["LOCATION"].ToString())
                                        {
                                            matched = true;
                                        }
                                    }
                                    if (!matched)
                                    {
                                        DataRow drUnMatchedRow = dtThirdTable.NewRow();
                                        drUnMatchedRow["CARD_NO"] = drFirstTableRow["CARD_NO"];
                                        drUnMatchedRow["QP_STAFF_NUMBER"] = drFirstTableRow["QP_STAFF_NUMBER"];
                                        drUnMatchedRow["LOCATION"] = drFirstTableRow["LOCATION"];
                                        dtThirdTable.Rows.Add(drUnMatchedRow);
                                    }
                                }

                                if (dtThirdTable.Rows.Count > 0)
                                {
                                    bc.WriteToServer(dtThirdTable);
                                    WriteToFile(dtThirdTable.Rows.Count.ToString() + " NEW RECORDS successfully ported into the destination server. " + DateTime.Now);
                                }
                                else
                                {
                                    WriteToFile("No new record updated in the destination server." + DateTime.Now);
                                }
                            }
                        }
                    }
                }

                // revert to previous user
                newUser1.Undo();
                newUser2.Undo();
            }
            catch (Exception ex)
            {
                WriteToFile("CRITICAL ERROR: " + ex + ". So, Service ended pre-maturedly at " + DateTime.Now);
            }
            //}
        }

        public WindowsImpersonationContext ImpersonateUser(string sUsername, string sDomain, string sPassword)
        {
            // initialize tokens
            IntPtr pExistingTokenHandle = new IntPtr(0);
            IntPtr pDuplicateTokenHandle = new IntPtr(0);
            pExistingTokenHandle = IntPtr.Zero;
            pDuplicateTokenHandle = IntPtr.Zero;

            // if domain name was blank, assume local machine
            if (sDomain == "")
                sDomain = System.Environment.MachineName;

            try
            {
                string sResult = null;

                const int LOGON32_PROVIDER_DEFAULT = 0;

                // create token
                const int LOGON32_LOGON_INTERACTIVE = 2;
                //const int SecurityImpersonation = 2;

                // get handle to token
                bool bImpersonated = LogonUser(sUsername, sDomain, sPassword,
                    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, ref pExistingTokenHandle);

                // did impersonation fail?
                if (false == bImpersonated)
                {
                    int nErrorCode = Marshal.GetLastWin32Error();
                    sResult = "LogonUser() failed with error code: " + nErrorCode + "\r\n";

                    // show the reason why LogonUser failed
                    WriteToFile("CRITICAL ERROR: " + sResult + ". So, Service ended pre-maturedly at " + DateTime.Now);
                }

                // Get identity before impersonation
                sResult += "Before impersonation: " + WindowsIdentity.GetCurrent().Name + "\r\n";

                bool bRetVal = DuplicateToken(pExistingTokenHandle, (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, ref pDuplicateTokenHandle);

                // did DuplicateToken fail?
                if (false == bRetVal)
                {
                    int nErrorCode = Marshal.GetLastWin32Error();
                    CloseHandle(pExistingTokenHandle); // close existing handle
                    sResult += "DuplicateToken() failed with error code: " + nErrorCode + "\r\n";

                    // show the reason why DuplicateToken failed
                    WriteToFile("CRITICAL ERROR: " + sResult + ". So, Service ended pre-maturedly at " + DateTime.Now);
                    return null;
                }
                else
                {
                    // create new identity using new primary token
                    WindowsIdentity newId = new WindowsIdentity(pDuplicateTokenHandle);
                    WindowsImpersonationContext impersonatedUser = newId.Impersonate();

                    // check the identity after impersonation
                    sResult += "After impersonation: " + WindowsIdentity.GetCurrent().Name + "\r\n";

                    WriteToFile("CRITICAL ERROR: " + sResult + ". So, Service ended pre-maturedly at " + DateTime.Now);
                    return impersonatedUser;
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
            finally
            {
                // close handle(s)
                if (pExistingTokenHandle != IntPtr.Zero)
                    CloseHandle(pExistingTokenHandle);
                if (pDuplicateTokenHandle != IntPtr.Zero)
                    CloseHandle(pDuplicateTokenHandle);
            }
        }
    }
}
