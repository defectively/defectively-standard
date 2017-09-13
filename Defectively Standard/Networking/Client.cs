using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Defectively.Standard.Cryptography;
using Newtonsoft.Json;

namespace Defectively.Standard.Networking
{
    /// <summary>
    ///     Provides a client to connect to a <see cref="Server"/> via TCP.
    /// </summary>
    public class Client : ConnectableBase
    {
        /// <summary>
        ///     The IP address of the <see cref="Client"/> this <see cref="Client"/> is connected to.
        /// </summary>
        /// <exception cref="SocketException"><see cref="Client"/> is not connected.</exception>
        public IPAddress Address => IPAddress.Parse(((IPEndPoint) client.Client.RemoteEndPoint).Address.ToString());

        /// <summary>
        ///     The identifier of the connection of this <see cref="Client"/>. Gets generated and set by the <see cref="Server"/>.
        /// </summary>
        public Guid SessionId { get; set; }

        private readonly TcpClient client;
        private StreamReader reader;
        private StreamWriter writer;

        /// <summary>
        ///     Initializes a new instance of the <see cref="Client"/> class.
        /// </summary>
        public Client() {
            client = new TcpClient();
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Client"/> class with a connected <see cref="TcpClient"/>.
        /// </summary>
        /// <param name="client">The connected <see cref="TcpClient"/>.</param>
        public Client(TcpClient client) {
            this.client = client;
            reader = new StreamReader(client.GetStream());
            writer = new StreamWriter(client.GetStream());
        }

        /// <summary>
        ///     Connects the <see cref="Client"/> asynchronously to the specified TCP port on the specified host.
        /// </summary>
        /// <param name="host">The name or IP address of the host.</param>
        /// <param name="port">The port to connect to.</param>
        /// <param name="submitCryptographicData">Set to "true" to use <see cref="Aes"/> encryption for all communications.</param>
        /// <remarks>Using <paramref name="submitCryptographicData" /> requires the <see cref="Client"/> to have valid <see cref="CryptographicData"/> set.</remarks>
        /// <returns>Returns a <see cref="Task"/> that represents the asynchronous connect operation.</returns>
        public async Task ConnectAsync(string host, int port, bool submitCryptographicData) {
            await client.ConnectAsync(host, port);
            reader = new StreamReader(client.GetStream());
            writer = new StreamWriter(client.GetStream());
            if (submitCryptographicData && CryptographicData.IsValid()) {
                var @params = await ReadAsync<RSAParameters>();
                var encrypted = CryptographyProvider.Instance.RSAEncrypt(JsonConvert.SerializeObject(CryptographicData), @params);
                await WriteRawAsync(encrypted);
                SessionId = Guid.Parse(await ReadAsync());
            }
            OnConnected(this, new ConnectedEventArgs());
        }

        /// <summary>
        ///     Disconnects the <see cref="Client"/> and releases the managed and unmanaged resources.
        /// </summary>
        public void Disconnect() {
            writer.Dispose();
            reader.Dispose();
            client.Dispose();
        }

        /// <summary>
        ///     Reads a line of characters asynchronously from the stream and returns the data as a string.
        /// </summary>
        /// <returns>Returns a <see cref="Task"/> that represents the asynchronous read operation. The value of the TResult parameter contains the next line from the stream.</returns>
        /// <remarks>The returned string will be decrypted if the <see cref="Client"/> has valid <see cref="CryptographicData"/> and the data seems encrypted (contains a "|").<para>Use the <see cref="ReadRawAsync"/> function to always get unhandled data.</para></remarks>
        /// <exception cref="ClientDisconnectedException">The <see cref="Client"/> isn't connected.</exception>
        /// <exception cref="HmacSignatureInvalidException">The signature is invalid or the data isn't encrypted but contains a "|".</exception>
        public async Task<string> ReadAsync() {
            if (CryptographicData == null || !CryptographicData.IsValid()) {
                return await ReadRawAsync();
            }

            var data = await ReadRawAsync();
            if (!data.Contains("|")) {
                return data;
            }

            var encrypted = data.Split('|')[0];
            var signature = data.Split('|')[1];

            if (!CryptographyProvider.Instance.HmacValidateSignature(encrypted, signature, CryptographicData)) {
                throw new HmacSignatureInvalidException();
            }

            return await CryptographyProvider.Instance.AesDecryptAsync(encrypted, CryptographicData);
        }

        /// <summary>
        ///     Reads a serialized object asynchronously from the stream and returns the data as <typeparamref name="TOut"/>.
        /// </summary>
        /// <typeparam name="TOut">The type of the expected object.</typeparam>
        /// <returns>Returns a <see cref="Task"/> that represents the asynchronous read operation. The value of the TResult parameter contains the deserialized object.</returns>
        /// <remarks>This function uses the <see cref="ReadAsync"/> function.<para>If the serialized data isn't encrypted but may contain a "|" use the <see cref="ReadRawAsync"/> function and deserialize the data manually.</para></remarks>
        /// <exception cref="ClientDisconnectedException">The <see cref="Client"/> isn't connected.</exception>
        /// <exception cref="JsonSerializationException">The data read isn't valid Json or does not represent a <typeparamref name="TOut"/> object.</exception>
        public async Task<TOut> ReadAsync<TOut>() {
            var serialized = await ReadAsync();
            return JsonConvert.DeserializeObject<TOut>(serialized);
        }

        /// <summary>
        ///     Reads a line of characters asynchronously from the stream and returns the data always unhandled.
        /// </summary>
        /// <returns>Returns a <see cref="Task"/> that represents the asynchronous read operation. The value of the TResult parameter contains the next line from the stream.</returns>
        /// <exception cref="ClientDisconnectedException">The <see cref="Client"/> isn't connected.</exception>
        public async Task<string> ReadRawAsync() {
            var data = await reader.ReadLineAsync();
            if (data == null) {
                OnDisconnected(this, new DisconnectedEventArgs(this));
                throw new ClientDisconnectedException(new DisconnectedEventArgs(this));
            }
            return data;
        }

        /// <summary>
        ///     Writes a line of characters asynchronously to the stream.
        /// </summary>
        /// <param name="s">The string to write to the stream.</param>
        /// <returns>Returns a <see cref="Task"/> that represents the asynchronous write operation.</returns>
        /// <remarks>The written string will be encrypted if the <see cref="Client"/> has valid <see cref="CryptographicData"/>.<para>Use the <see cref="WriteRawAsync"/> function to always write data unhandled.</para></remarks>
        public async Task WriteAsync(string s) {
            if (CryptographicData == null || !CryptographicData.IsValid()) {
                await WriteRawAsync(s);
            } else {
                var encrypted = await CryptographyProvider.Instance.AesEncryptAsync(s, CryptographicData);
                var signature = CryptographyProvider.Instance.HmacCreateSignature(encrypted, CryptographicData);

                await writer.WriteLineAsync($"{encrypted}|{signature}");
                await writer.FlushAsync();
            }
        }

        /// <summary>
        ///     Writes a serialized object asynchronously to the stream.
        /// </summary>
        /// <param name="o">The object to serialize and write to the stream.</param>
        /// <returns>Returns a <see cref="Task"/> that represents the asynchronous write operation.</returns>
        /// <remarks>The serialized object will be encrypted if the <see cref="Client"/> has valid <see cref="CryptographicData"/>.<para>Manually serialize the object and use the <see cref="WriteRawAsync"/> function to always write data unhandled.</para></remarks>
        public async Task WriteAsync(object o) {
            var serialized = JsonConvert.SerializeObject(o);
            await WriteAsync(serialized);
        }

        /// <summary>
        ///     Writes a line of characters unhandled asynchronously to the stream.
        /// </summary>
        /// <param name="s">The string to write to the stream.</param>
        /// <returns>Returns a <see cref="Task"/> that represents the asynchronous write operation.</returns>
        public async Task WriteRawAsync(string s) {
            await writer.WriteLineAsync(s);
            await writer.FlushAsync();
        }
    }
}
