# Defectively Standard
Defectively Standard is an easy-to-use, asynchronous TCP client-server .NET Standard library with AES encryption.

## Examples
### Creating and Starting a new Server
```csharp
using System;
using System.Threading.Tasks;
using Defectively.Standard.Cryptography;
using Defectively.Standard.Networking;

private int port = 1337;
private Server server;

private async void OnStartServerClick(object sender, EventArgs e) {
    server = new Server(port);
    server.Connected += OnServerConnected;
    await server.Start(true); // set to false if you don't wish to use AES encryption
}

private async void OnServerConnected(ConnectableBase sender, ConnectedEventArgs e) {
    lbxConnectedClients.Items.Add(e.Client.Address.ToString())
    await ListenToConnection(e.Client);
}

private async Task ListenToConnection(Client client) {
    while (true) {
        var content = await client.ReadAsync();
        this.Invoke(new Action(() => lblReceived.Text = content));
    }
}
```

### Creating and Connecting a new Client
```csharp
using System;
using System.Threading.Tasks;
using Defectively.Standard.Cryptography;
using Defectively.Standard.Networking;

private string host = "localhost";
private int port = 1337;
private Client client;

private async void OnConnectClick(object sender, EventArgs e) {
    client = new Client { CryptographicData = CryptographyProvider.Instance.GetRandomData() };
    await client.ConnectAsync(host, port, true); // don't set CryptographicData and set to false if you don't wish to use AES encryption
}
```

### Sending a Basic String
```csharp
using System;
using System.Threading.Tasks;
using Defectively.Standard.Cryptography;
using Defectively.Standard.Networking;

private Client client;

private async void OnInputKeyDown(object sender, KeyDownEventArgs e) {
    if (e.KeyCode == Keys.Enter) {
        await client.WriteAsync(((TextBox) sender).Text);
    }
}
```

### Sending and Receiving an Object
```csharp
using System;
using System.Threading.Tasks;
using Defectively.Standard.Cryptography;
using Defectively.Standard.Networking;

private Client client;
private Server server;

// Client
private async Task ...() {
    await client.WriteAsync("example") // notify the server that the next message contains an object
    var data = new ExampleClass();
    await client.WriteAsync(data);
}

// Server
private async Task ListenToConnection(Client client) {
    while (true) {
        var content = await client.ReadAsync();
        
        if (content == "example") { // basic protocol check
            var data = await client.ReadAsync<ExampleClass>();
        }
    }
}
```

## License
MIT