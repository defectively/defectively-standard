using System;

namespace Defectively.Standard.Networking
{
    /// <summary>
    ///     Provides data for the <see cref="ConnectableBase.Disconnected"/> event handler.
    /// </summary>
    public class DisconnectedEventArgs : EventArgs
    {
        /// <summary>
        ///     The <see cref="Networking.Client"/> that connected.
        /// </summary>
        public Client Client { get; }

        /// <inheritdoc />
        public DisconnectedEventArgs() { }

        /// <inheritdoc />
        public DisconnectedEventArgs(Client client) {
            Client = client;
        }
    }
}
