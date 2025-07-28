using AzureAgentToM365ATK;
using AzureAgentToM365ATK.Agent;
using Microsoft.Agents.Builder;
using Microsoft.Agents.Hosting.AspNetCore;
using Microsoft.Agents.Storage;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

if (builder.Environment.IsDevelopment())
{
    builder.Configuration.AddUserSecrets<Program>();
}

builder.Services.AddControllers();
builder.Services.AddHttpClient("WebClient", client => client.Timeout = TimeSpan.FromSeconds(600));
builder.Services.AddHttpContextAccessor();
builder.Logging.AddConsole();

// Register Semantic Kernel
builder.Services.AddKernel();

// Agent SDK Registrations: 
builder.Services.AddCloudAdapter();
builder.Services.AddAgentAspNetAuthentication(builder.Configuration);
builder.AddAgentApplicationOptions();
builder.AddAgent<AzureAgent>();
builder.Services.AddSingleton<IStorage, MemoryStorage>();


WebApplication app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

// Register the agent application endpoint for incoming messages.
var incomingRoute = app.MapPost("/api/messages", async (HttpRequest request, HttpResponse response, IAgentHttpAdapter adapter, IAgent agent, CancellationToken cancellationToken) =>
{
    await adapter.ProcessAsync(request, response, agent, cancellationToken);
});

// Left to allow you to add controllers if you wish later.
if (app.Environment.IsDevelopment() || app.Environment.EnvironmentName == "TestTool")
{
    app.MapGet("/", () => "Microsoft Agents SDK From Azure AI Foundry Agent Service Sample");
    app.UseDeveloperExceptionPage();
    app.MapControllers().AllowAnonymous();
}
else
{
    app.MapControllers();
}
app.Run();