/**
 * @file sidpbind.cs
 * @brief SIDP Library interoperability interface with C#
 */

/*
   Secure Inter-Device Protocol Library

   Copyright 2012-2014 Pedro A. Hortas (pah@ucodev.org)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/


using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices; // DllImport
using System.Text; // StringBuilder
using System.Net;
using System.Net.Sockets;

namespace sidpbind
{
	public class SIDP {
		protected static int pkt_hdrs_max_len() {
			return 1024;
		}

		public static int pkt_max_len() {
			return 65535;
		}

		public static int pkt_msg_max_len() {
			return pkt_max_len() - pkt_hdrs_max_len();
		}

		public enum msgtype {
			SIDP_MSG_TYPE_DATA,
			SIDP_MSG_TYPE_AUTH,
			SIDP_MSG_TYPE_NEGOTIATE
		}
		
		public enum support {
			SIDP_SUPPORT_CIPHER_AES256_FL,
			SIDP_SUPPORT_CIPHER_XSALSA20_FL,
			SIDP_SUPPORT_COMPRESS_LZO_FL,
			SIDP_SUPPORT_COMPRESS_ZLIB_FL,
			SIDP_SUPPORT_ENCAP_DEFAULT_FL
		}
		
		public enum negotiate {
			SIDP_NEGOTIATE_CIPHER_AES256_FL,
			SIDP_NEGOTIATE_CIPHER_XSALSA20_FL,
			SIDP_NEGOTIATE_COMPRESS_LZO_FL,
			SIDP_NEGOTIATE_COMPRESS_ZLIB_FL,
			SIDP_NEGOTIATE_ENCAP_DEFAULT_FL
		}
		public enum status {
			SIDP_NEGOTIATED_FL,
			SIDP_AUTHENTICATED_FL
		}
	
		[StructLayout(LayoutKind.Sequential)]
		public unsafe struct sidppkt {
			public uint sdev;
			public uint ddev;
			public uint sid;
			public ushort msg_size;
			public void *msg;
		}
		
		[StructLayout(LayoutKind.Sequential)]
		public unsafe struct sidpconn {
			public int fd;
			public uint sdev;
			public uint ddev;
			public uint sid;
			public fixed byte key[32];
			public uint negotiate_flags;
			public uint support_flags;
			public uint status_flags;
		}
		
		[StructLayout(LayoutKind.Sequential)]
		public unsafe struct sidpopt {
			public ushort session_type;
			public ushort compress_type;
			public ushort cipher_type;
			public ushort msg_type;
			public fixed char key[32];
		}
		
		[DllImport("libsidp.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
		public static unsafe extern void sidp_pkt_set_opt(ref sidpopt opt, ushort session_type, ushort cipher_type, ushort compress_type, ushort msg_type, String key);
		
		[DllImport("libsidp.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
		public static unsafe extern void sidp_conn_init(ref sidpconn conn, int fd, uint sdev, uint ddev, String key);
		
		[DllImport("libsidp.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
		public static unsafe extern void sidp_conn_set_support(ref sidpconn conn, uint flag);
		
		[DllImport("libsidp.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
		public static unsafe extern int sidp_conn_close(ref sidpconn conn);
		
		[DllImport("libsidp.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
		public static unsafe extern int sidp_seq_auth_user(ref sidpconn conn, String user, String pass);
		
		[DllImport("libsidp.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
		public static unsafe extern int sidp_seq_auth_host(ref sidpconn conn, String user, String pass);
		
		[DllImport("libsidp.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
		public static unsafe extern int sidp_seq_negotiation_user(ref sidpconn conn);
		
		[DllImport("libsidp.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
		public static unsafe extern int sidp_seq_negotiation_host(ref sidpconn conn);
		
		[DllImport("libsidp.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
		public static unsafe extern int sidp_seq_data_send(ref sidpconn conn, String data, uint len);
		
		[DllImport("libsidp.dll", CharSet=CharSet.Ansi, CallingConvention=CallingConvention.Cdecl)]
		public static unsafe extern int sidp_seq_data_recv(ref sidpconn conn, StringBuilder data, ref uint len);
	}
	
	public partial class MainForm : Form
	{
		public unsafe MainForm()
		{
			/* Connect to remote device */
			TcpClient tcpclient = new TcpClient();
			tcpclient.Connect("172.16.1.101", 6767);

			/* Create SIDP connection */
			SIDP.sidpconn conn = new SIDP.sidpconn();
			SIDP.sidp_conn_init(ref conn, (int) tcpclient.Client.Handle, 30, 40, "test123");
			
			/* Set support flags */
			SIDP.sidp_conn_set_support(ref conn, (uint) SIDP.support.SIDP_SUPPORT_CIPHER_AES256_FL);
			SIDP.sidp_conn_set_support(ref conn, (uint) SIDP.support.SIDP_SUPPORT_COMPRESS_LZO_FL);
			SIDP.sidp_conn_set_support(ref conn, (uint) SIDP.support.SIDP_SUPPORT_ENCAP_DEFAULT_FL);
			
			/* Start authentication */
			SIDP.sidp_seq_auth_user(ref conn, "test", "test123");
			
			/* Start negotiation */
			SIDP.sidp_seq_negotiation_user(ref conn);
			
			/* Send data */
			SIDP.sidp_seq_data_send(ref conn, "This is a Win32 message", 24);
			
			/* Receive data */
			uint len = new uint();
			StringBuilder recvdata = new StringBuilder(SIDP.pkt_msg_max_len());
			SIDP.sidp_seq_data_recv(ref conn, recvdata, ref len);
			
			/* Show data */
			MessageBox.Show(recvdata.ToString());
			

			/* Some examples of accessing parameters of SIDP objects */
			byte[] arr = new byte[32];
			for (int i = 0; i != 32; i++) {
				arr[i] = conn.key[i];
			}

			System.Text.Encoding enc = System.Text.Encoding.ASCII;
			String s = enc.GetString(arr);

			/* Show conn.key */
			MessageBox.Show(s);
			
			/* Show conn.support_flags */
			MessageBox.Show(conn.support_flags.ToString());
		}
	}
}

