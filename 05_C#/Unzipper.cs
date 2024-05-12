// See https://aka.ms/new-console-template for more information

using System.IO.Compression;

Console.WriteLine(Unzipper.Unzip("8/B2jYz38Xd29In3dXT28PRzjQn2dwsJdwxyjfHNTC7KL85PK4lxLqosKMlPL0osyKgEAA=="));
Console.WriteLine(Unzipper.Unzip("801MzsjMS3UvzUwBAA=="));


public class Unzipper {

    		public static string Unzip(string input)
		{
			if (string.IsNullOrEmpty(input))
			{
				return input;
			}
			try
			{
				byte[] bytes = Decompress(Convert.FromBase64String(input));
				return System.Text.Encoding.UTF8.GetString(bytes);
			}
			catch (Exception)
			{
				return input;
			}
	}

		public static byte[] Decompress(byte[] input)
		{
			using MemoryStream stream = new MemoryStream(input);
			using MemoryStream memoryStream = new MemoryStream();
			using (DeflateStream deflateStream = new DeflateStream(stream, CompressionMode.Decompress))
			{
				deflateStream.CopyTo(memoryStream);
			}
			return memoryStream.ToArray();
		}
}