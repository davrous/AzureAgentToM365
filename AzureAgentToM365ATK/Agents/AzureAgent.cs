// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Azure;
using Azure.AI.Agents.Persistent;
using Azure.AI.Projects;
using Azure.Identity;
using Microsoft.Agents.Builder;
using Microsoft.Agents.Builder.App;
using Microsoft.Agents.Builder.State;
using Microsoft.Agents.Core.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.Agents;
using Microsoft.SemanticKernel.Agents.AzureAI;
using Microsoft.SemanticKernel.ChatCompletion;

namespace AzureAgentToM365ATK.Agent;

public class AzureAgent : AgentApplication
{
    private readonly PersistentAgentsClient _aiProjectClient;
    private AzureAIAgent _existingAgent;
    private string _agentId;
    private AgentThread _agentThread;

    public AzureAgent(AgentApplicationOptions options, IConfiguration configuration) : base(options)
    {
        OnConversationUpdate(ConversationUpdateEvents.MembersAdded, WelcomeMessageAsync);
        OnActivity(ActivityTypes.Message, MessageActivityAsync, rank: RouteRank.Last);

        // TO DO: get the connection string of your Azure AI Foundry project in the portal
        string connectionString = configuration["AIServices:AzureAIFoundryProjectEndpoint"];
        if (string.IsNullOrEmpty(connectionString))
        {
            throw new InvalidOperationException("AzureAIFoundryProjectEndpoint is not configured.");
        }
        // TO DO: Get the assistant ID in the Azure AI Foundry project portal for your agent
        this._agentId = configuration["AIServices:AgentID"];
        if (string.IsNullOrEmpty(this._agentId))
        {
            throw new InvalidOperationException("AgentID is not configured.");
        }

        _aiProjectClient = new PersistentAgentsClient(connectionString, new DefaultAzureCredential());
    }

    protected async Task MessageActivityAsync(ITurnContext turnContext, ITurnState turnState, CancellationToken cancellationToken)
    {
        Console.WriteLine($"\nUser message received: {turnContext.Activity.Text}\n");
        ChatHistory chatHistory = turnState.GetValue("conversation.chatHistory", () => new ChatHistory());
        await SendMessageToAzureAgent(turnContext.Activity.Text, turnContext);
    }

    protected async Task InitializeAzureAgent()
    {
        var agentModel = await this._aiProjectClient.Administration.GetAgentAsync(this._agentId);
        this._existingAgent = new AzureAIAgent(agentModel, this._aiProjectClient);
        this._agentThread = new AzureAIAgentThread(this._existingAgent.Client);
    }

    protected async Task SendMessageToAzureAgent(string Text, ITurnContext turnContext)
    {
        try
        {
            // Start a Streaming Process 
            await turnContext.StreamingResponse.QueueInformativeUpdateAsync("Working on a response for you");

            if (this._existingAgent == null)
            {
                await InitializeAzureAgent();
            }

            // Create a new message to send to the Azure agent
            ChatMessageContent message = new(AuthorRole.User, Text);
            // Send the message to the Azure agent and get the response
            await foreach (StreamingChatMessageContent response in _existingAgent.InvokeStreamingAsync(message, this._agentThread))
            {
                turnContext.StreamingResponse.QueueTextChunk(response.Content);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error sending message to Azure agent: {ex.Message}");
            turnContext.StreamingResponse.QueueTextChunk("An error occurred while processing your request.");
        }
        finally
        {
            await turnContext.StreamingResponse.EndStreamAsync(); // End the streaming response
        }
    }

    protected async Task WelcomeMessageAsync(ITurnContext turnContext, ITurnState turnState, CancellationToken cancellationToken)
    {
        foreach (ChannelAccount member in turnContext.Activity.MembersAdded)
        {
            if (member.Id != turnContext.Activity.Recipient.Id)
            {
                await turnContext.SendActivityAsync(MessageFactory.Text("Hello and Welcome to the Stocks agent!"), cancellationToken);
            }
        }
    }
}
