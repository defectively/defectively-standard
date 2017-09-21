using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Defectively.Standard.Cryptography;
using Newtonsoft.Json;

// ReSharper disable InconsistentNaming

namespace Defectively.Standard.Networking
{
    /// <summary>
    ///     Listens for connections from TCP <see cref="Client"/>s.
    /// </summary>
    public class Server : ConnectableBase
    {
        /// <summary>
        ///     A list containing all connected <see cref="Client"/>s.
        /// </summary>
        public IReadOnlyList<Client> ConnectedClients => clients.AsReadOnly();

        private readonly TcpListener listener;
        private TcpClient client;
        private readonly List<Client> clients = new List<Client>();
        private RSAParameters publicRSAParams;
        private RSAParameters privateRSAParams;

        /// <summary>
        ///     Initializes a new instance of the <see cref="Server"/> class with the specified port.
        /// </summary>
        /// <param name="port">The port to listen on.</param>
        public Server(int port) {
            listener = new TcpListener(IPAddress.Any, port);
        }

        /// <summary>
        ///     Disconnects each <see cref="Client"/> and releases the managed and unmanaged resources.
        /// </summary>
        public void Dispose() {
            clients.ForEach(c => c.Disconnect());
            clients.Clear();
            client.Dispose();
        }
        
        private void OnClientDisconnected(ConnectableBase sender, DisconnectedEventArgs e) {
            e.Client.Disconnected -= OnClientDisconnected;
            OnDisconnected(this, e);
        }

        /// <summary>
        ///     Removes all the <see cref="Client"/>s that match the conditions defined by the specified predicate.
        /// </summary>
        /// <param name="predicate">The <see cref="Predicate{T}"/> delegate that defines the conditions of the <see cref="Client"/>s to remove.</param>
        public void RemoveAllClients(Predicate<Client> predicate) {
            clients.RemoveAll(predicate);
        }

        /// <summary>
        ///     Starts the <see cref="Server"/> asynchronously and waits for incoming connections.
        /// </summary>
        /// <param name="secure">Set to "true" to use <see cref="Aes"/> encryption for all communications.</param>
        /// <remarks>Using <paramref name="secure" /> requires each connecting client <see cref="Client"/> to have valid <see cref="CryptographicData"/> set.</remarks>
        /// <returns>Returns a <see cref="Task"/> that represents the asynchronous start operation.</returns>
        public async Task StartAsync(bool secure) {
            listener.Start();

            if (secure) {
                using (var rsa = new RSACng(4096)) {
                    publicRSAParams = rsa.ExportParameters(false);
                    privateRSAParams = rsa.ExportParameters(true);
                }
            }

            while (true) {
                client = await listener.AcceptTcpClientAsync();

                var connectedClient = new Client(client);
                connectedClient.Disconnected += OnClientDisconnected;
                if (secure) {
                    await connectedClient.WriteAsync(publicRSAParams);
                    var decrypted = CryptographyProvider.Instance.RSADecrypt(await connectedClient.ReadRawAsync(), privateRSAParams);
                    connectedClient.CryptographicData = JsonConvert.DeserializeObject<CryptographicData>(decrypted);
                    var sessionId = Guid.NewGuid();
                    connectedClient.SessionId = sessionId;
                    await connectedClient.WriteAsync(sessionId.ToString());
                }
                clients.Add(connectedClient);

                OnConnected(this, new ConnectedEventArgs(connectedClient));
            }
        }

        /// <summary>
        ///     Stops the <see cref="Server"/>.
        /// </summary>
        public void Stop() {
            listener.Stop();
        }
    }
}
