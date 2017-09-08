using System;

namespace Defectively.Standard.Networking
{
    /// <inheritdoc />
    public class ClientDisconnectedException : Exception
    {
        /// <summary />
        public DisconnectedEventArgs Args { get; }

        /// <summary>
        ///     Initializes a new instance of the <see cref="ClientDisconnectedException"/> class with the specified <see cref="DisconnectedEventArgs"/>.
        /// </summary>
        /// <param name="e"></param>
        public ClientDisconnectedException(DisconnectedEventArgs e) {
            Args = e;
        }
    }
}
