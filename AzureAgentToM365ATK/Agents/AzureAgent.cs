// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Use this flag to enable the Playground mode, which allows the agent to run without user authentication.
#define PLAYGROUND

using Azure;
using Azure.AI.Agents.Persistent;
#if PLAYGROUND
using Azure.Identity;
#endif
using Microsoft.Agents.Builder;
using Microsoft.Agents.Builder.App;
using Microsoft.Agents.Builder.State;
using Microsoft.Agents.Core.Models;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.Agents.AzureAI;
using Microsoft.SemanticKernel.ChatCompletion;
using System.Collections.Concurrent;

namespace AzureAgentToM365ATK.Agent;

public class AzureAgent : AgentApplication
{
    // This is a cache to store the agent model for the Azure AI Foundry agent as this object uses private serializer and virtual objects and is expensive to create.
    // This cache will store the returned model by agent ID. if you need to change the agent model you would need to clear this cache. 
    private static ConcurrentDictionary<string, Response<PersistentAgent>> _agentModelCache = new();

    private readonly string _agentId;
    private readonly string _connectionStringForAgent;

    public AzureAgent(AgentApplicationOptions options, IConfiguration configuration) : base(options)
    {
        
        // TO DO: get the connection string of your Azure AI Foundry project in the portal
        this._connectionStringForAgent = configuration["AIServices:AzureAIFoundryProjectEndpoint"];
        if (string.IsNullOrEmpty(_connectionStringForAgent))
        {
            throw new InvalidOperationException("AzureAIFoundryProjectEndpoint is not configured.");
        }
        
        // TO DO: Get the assistant ID in the Azure AI Foundry project portal for your agent
        this._agentId = configuration["AIServices:AgentID"];
        if (string.IsNullOrEmpty(this._agentId))
        {
            throw new InvalidOperationException("AgentID is not configured.");
        }

        // Setup Agent with Route handlers to manage connecting and responding from the Azure AI Foundry agent.

        // This is handing the events describing when a user is added to the conversation. 
        OnConversationUpdate(ConversationUpdateEvents.MembersAdded, SendWelcomeMessageAsync);

        // This is handling the sign out event, which will clear the user authorization token.
        OnMessage("--signout", HandleSignOutAsync);

        // This is handling the clearing of the agent model cache without needing to restart the agent. 
        OnMessage("--clearcache", HandleClearingModelCacheAsync);

        // This is handling the message activity, which will send the user message to the Azure AI Foundry agent.
        // we are also indicating which auth profile we want to have available for this handler.
#if PLAYGROUND
        OnActivity(ActivityTypes.Message, SendMessageToAzureAgent);
#else
        OnActivity(ActivityTypes.Message, SendMessageToAzureAgent, autoSignInHandlers: ["AIFoundry"]);
#endif

    }

    /// <summary>
    /// This handler is called when the MeebersAdded event is triggered in the conversation.
    /// </summary>
    /// <param name="turnContext"></param>
    /// <param name="turnState"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    protected async Task SendWelcomeMessageAsync(ITurnContext turnContext, ITurnState turnState, CancellationToken cancellationToken)
    {
        foreach (ChannelAccount member in turnContext.Activity.MembersAdded)
        {
            if (member.Id != turnContext.Activity.Recipient.Id)
            {
                await turnContext.SendActivityAsync(MessageFactory.Text("Hello and Welcome to the Stocks agent!"), cancellationToken);
            }
        }
    }

    /// <summary>
    /// Handle the clearing of the agent model cache.
    /// </summary>
    /// <param name="turnContext"></param>
    /// <param name="turnState"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    private async Task HandleClearingModelCacheAsync(ITurnContext turnContext, ITurnState turnState, CancellationToken cancellationToken)
    {
        _agentModelCache.Clear();
        await turnContext.SendActivityAsync("The agent model cache has been cleared.", cancellationToken: cancellationToken);
        Console.WriteLine("The agent model cache has been cleared.");
    }

    /// <summary>
    /// Handle the sign out event, and clear the logged in user token
    /// </summary>
    /// <param name="turnContext"></param>
    /// <param name="turnState"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    private async Task HandleSignOutAsync(ITurnContext turnContext, ITurnState turnState, CancellationToken cancellationToken)
    {
        await UserAuthorization.SignOutUserAsync(turnContext, turnState, cancellationToken: cancellationToken);
        await turnContext.SendActivityAsync("You have signed out", cancellationToken: cancellationToken);
    }

    /// <summary>
    /// This method sends the user message ( just text in this example ) to the Azure AI Foundry agent and streams the response back to the user.
    /// </summary>
    /// <param name="turnContext"></param>
    /// <param name="turnState"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    protected async Task SendMessageToAzureAgent(ITurnContext turnContext, ITurnState turnState, CancellationToken cancellationToken)
    {
        Console.WriteLine($"\nUser message received: {turnContext.Activity.Text}\n");
        try
        {
            // Start a Streaming Process to let clients that support streaming know that we are processing the request. 
            await turnContext.StreamingResponse.QueueInformativeUpdateAsync("Just a moment please..", cancellationToken).ConfigureAwait(false);

            // Set up the PersistentAgentsClient to communicate with the Azure AI Foundry agent.
#if PLAYGROUND
            PersistentAgentsClient _aiProjectClient = new PersistentAgentsClient(this._connectionStringForAgent, new DefaultAzureCredential());
#else
            // This is a helper class to generate an OBO User Token for the Azure AI Foundry agent from the current user authorization.
            PersistentAgentsClient _aiProjectClient = new PersistentAgentsClient(this._connectionStringForAgent, 
                        // This is a helper class to generate an OBO User Token for the Azure AI Foundry agent from the current user authorization.
                        new UserAuthorizationTokenWrapper(UserAuthorization, turnContext, "AIFoundry"));
#endif

            // Get the requested agent by ID.
            Response<PersistentAgent> agentModel = _agentModelCache.TryGetValue(this._agentId, out var cachedModel) ? cachedModel : null;
            if (agentModel == null)
            {
                // subtle hint to the client that the agent model is being fetched.
                await turnContext.StreamingResponse.QueueInformativeUpdateAsync("Arranging deck chairs.", cancellationToken).ConfigureAwait(false);

                // If the agent model is not found in the conversation state, fetch it from the Azure AI Foundry project.
                agentModel = await _aiProjectClient.Administration.GetAgentAsync(this._agentId).ConfigureAwait(false);
                // Cache the agent model for future use.
                _agentModelCache.TryAdd(this._agentId, agentModel);
            }
            
            // Create an instance of the AzureAIAgent with the agent model and client.
            AzureAIAgent _existingAgent = new AzureAIAgent(agentModel, _aiProjectClient);

            AzureAIAgentThread _agentThread = null; 
            // Get or create thread: 
            string agentThreadId = turnState.Conversation.GetValue<string>("conversation.threadId", () => null);
            if (string.IsNullOrEmpty(agentThreadId))
            {
                // Create a new thread for the agent if it doesn't exist
                _agentThread = new AzureAIAgentThread(_existingAgent.Client);
            }
            else
            {
                // Use the existing thread
                _agentThread = new AzureAIAgentThread(_existingAgent.Client, agentThreadId);
            }

            // Inform the client that we are working on a response
            await turnContext.StreamingResponse.QueueInformativeUpdateAsync("Flagging stock traders down..", cancellationToken).ConfigureAwait(false);

            // Create a new message to send to the Azure agent
            ChatMessageContent message = new(AuthorRole.User, turnContext.Activity.Text);
            // Send the message to the Azure agent and get the response
            // This will handle text responses,  if you want to handle attachments and other content types, you would need to extend this method.
            await foreach (StreamingChatMessageContent response in _existingAgent.InvokeStreamingAsync(message, _agentThread))
            {
                if(!string.IsNullOrEmpty(response.Content))
                    turnContext.StreamingResponse.QueueTextChunk(response.Content);
                else
                    turnContext.StreamingResponse.QueueTextChunk("No response from the Azure agent.");
            }
            turnState.Conversation.SetValue("conversation.threadId", _agentThread.Id);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error sending message to Azure agent: {ex.Message}");
            turnContext.StreamingResponse.QueueTextChunk("An error occurred while processing your request.");
        }
        finally
        {
            await turnContext.StreamingResponse.EndStreamAsync(cancellationToken).ConfigureAwait(false); // End the streaming response
        }
    }
}
