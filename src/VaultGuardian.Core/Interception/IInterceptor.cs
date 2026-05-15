namespace VaultGuardian.Core.Interception;

public interface IInterceptor : IAsyncDisposable
{
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync();
}
