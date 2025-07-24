using AzureAgentToM365ATK;
using AzureAgentToM365ATK.Agent;
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
builder.Services.AddCloudAdapter<AdapterWithErrorHandler>();
builder.Logging.AddConsole();

// Register Semantic Kernel
builder.Services.AddKernel();

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