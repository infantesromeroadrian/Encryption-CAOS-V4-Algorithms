/**
 * Asistente IA Flotante
 * 
 * Este script maneja la funcionalidad de la burbuja flotante del asistente IA.
 * Permite al usuario interactuar con el asistente desde cualquier página de la aplicación.
 */

document.addEventListener('DOMContentLoaded', function() {
    // Referencias a elementos DOM
    const assistantBubble = document.getElementById('ai-assistant-bubble');
    const assistantModal = document.getElementById('ai-assistant-modal');
    const closeButton = document.getElementById('ai-assistant-close');
    const chatForm = document.getElementById('ai-assistant-form');
    const userInput = document.getElementById('ai-assistant-input');
    const chatBody = document.getElementById('ai-assistant-body');
    const statusIndicator = document.getElementById('ai-status-indicator');
    
    // Variable para almacenar el estado del sistema RAG
    let ragAvailable = false;
    
    // Verificar el estado del sistema RAG
    checkRAGStatus();
    
    // Mostrar/ocultar modal al hacer clic en la burbuja
    assistantBubble.addEventListener('click', function() {
        assistantModal.classList.toggle('active');
        // Hacer scroll al final del chat
        chatBody.scrollTop = chatBody.scrollHeight;
    });
    
    // Cerrar modal al hacer clic en el botón de cierre
    closeButton.addEventListener('click', function() {
        assistantModal.classList.remove('active');
    });
    
    // Manejar envío del formulario
    chatForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const userMessage = userInput.value.trim();
        if (!userMessage) return;
        
        // Agregar mensaje del usuario al chat
        addUserMessage(userMessage);
        userInput.value = '';
        
        // Mostrar indicador de escritura
        showTypingIndicator();
        
        // Enviar mensaje al backend
        sendMessage(userMessage);
    });
    
    /**
     * Verifica el estado del sistema RAG
     */
    async function checkRAGStatus() {
        try {
            const response = await fetch('/rag/status');
            const data = await response.json();
            
            ragAvailable = data.available;
            
            // Actualizar indicador de estado
            if (ragAvailable) {
                statusIndicator.textContent = 'En línea';
                statusIndicator.className = 'ai-status-indicator online';
            } else {
                statusIndicator.textContent = 'Limitado';
                statusIndicator.className = 'ai-status-indicator offline';
                
                // Agregar mensaje de advertencia
                const warningMsg = 'Estoy funcionando en modo limitado. Algunas respuestas pueden no ser precisas.';
                addAssistantMessage(warningMsg);
            }
        } catch (error) {
            console.error('Error al verificar estado RAG:', error);
            ragAvailable = false;
            statusIndicator.textContent = 'Offline';
            statusIndicator.className = 'ai-status-indicator offline';
            
            // Agregar mensaje de error
            addAssistantMessage('Estoy funcionando en modo offline. Mis respuestas serán limitadas.');
        }
    }
    
    /**
     * Envía un mensaje al backend
     */
    async function sendMessage(message) {
        try {
            const url = ragAvailable ? '/rag/query' : '/rag/fallback_query';
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ query: message })
            });
            
            const data = await response.json();
            
            // Ocultar indicador de escritura
            hideTypingIndicator();
            
            // Si hay un error, mostrar el mensaje de error
            if (data.error) {
                addAssistantMessage(data.response || 'Lo siento, ha ocurrido un error. Por favor, intenta más tarde.');
                return;
            }
            
            // Agregar respuesta del asistente
            addAssistantMessage(data.response);
            
            // Si hay fuentes, mostrarlas
            if (data.sources && data.sources.length > 0) {
                const sourcesArray = [];
                
                // Procesar las fuentes para asegurar que sean strings
                data.sources.forEach(source => {
                    if (typeof source === 'string') {
                        sourcesArray.push(source);
                    } else if (source && typeof source === 'object') {
                        // Si es un objeto, intentar extraer información útil
                        if (source.title) {
                            sourcesArray.push(source.title);
                        } else if (source.document) {
                            sourcesArray.push(source.document);
                        } else if (source.id) {
                            sourcesArray.push(`Documento ID: ${source.id}`);
                        } else {
                            // Si no hay información útil, convertir a JSON
                            sourcesArray.push(JSON.stringify(source));
                        }
                    }
                });
                
                if (sourcesArray.length > 0) {
                    addSources(sourcesArray);
                }
            }
            
        } catch (error) {
            console.error('Error al enviar mensaje:', error);
            hideTypingIndicator();
            addAssistantMessage('Lo siento, ha ocurrido un error al procesar tu mensaje. Por favor, intenta de nuevo más tarde.');
        }
    }
    
    /**
     * Agrega un mensaje del usuario al chat
     */
    function addUserMessage(message) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'ai-message user';
        
        const messageContent = document.createElement('div');
        messageContent.className = 'message-content';
        messageContent.textContent = message;
        
        messageDiv.appendChild(messageContent);
        chatBody.appendChild(messageDiv);
        
        // Hacer scroll al final del chat
        chatBody.scrollTop = chatBody.scrollHeight;
    }
    
    /**
     * Agrega un mensaje del asistente al chat
     */
    function addAssistantMessage(message) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'ai-message assistant';
        
        const messageContent = document.createElement('div');
        messageContent.className = 'message-content';
        
        // Si el mensaje contiene markdown, procesarlo
        if (typeof marked !== 'undefined') {
            try {
                messageContent.innerHTML = marked.parse(message);
            } catch (e) {
                console.error('Error al procesar markdown:', e);
                messageContent.textContent = message;
            }
        } else {
            messageContent.textContent = message;
        }
        
        messageDiv.appendChild(messageContent);
        chatBody.appendChild(messageDiv);
        
        // Hacer scroll al final del chat
        chatBody.scrollTop = chatBody.scrollHeight;
        
        // Si hay highlight.js, aplicarlo
        if (typeof hljs !== 'undefined') {
            document.querySelectorAll('pre code').forEach((block) => {
                hljs.highlightBlock(block);
            });
        }
    }
    
    /**
     * Agrega fuentes al chat
     */
    function addSources(sources) {
        if (!sources || sources.length === 0) return;
        
        const sourcesDiv = document.createElement('div');
        sourcesDiv.className = 'ai-message assistant';
        
        const sourcesContent = document.createElement('div');
        sourcesContent.className = 'message-content sources';
        
        const sourcesTitle = document.createElement('p');
        sourcesTitle.textContent = 'Fuentes:';
        sourcesTitle.style.fontWeight = 'bold';
        sourcesTitle.style.fontSize = '0.8rem';
        sourcesTitle.style.marginBottom = '5px';
        
        sourcesContent.appendChild(sourcesTitle);
        
        const sourcesList = document.createElement('ul');
        sourcesList.style.fontSize = '0.8rem';
        sourcesList.style.paddingLeft = '20px';
        sourcesList.style.margin = '0';
        
        sources.forEach(source => {
            if (source) {
                const sourceItem = document.createElement('li');
                sourceItem.textContent = source.toString();
                sourcesList.appendChild(sourceItem);
            }
        });
        
        sourcesContent.appendChild(sourcesList);
        sourcesDiv.appendChild(sourcesContent);
        chatBody.appendChild(sourcesDiv);
        
        // Hacer scroll al final del chat
        chatBody.scrollTop = chatBody.scrollHeight;
    }
    
    /**
     * Muestra el indicador de escritura
     */
    function showTypingIndicator() {
        const typingDiv = document.createElement('div');
        typingDiv.className = 'ai-typing-indicator';
        typingDiv.id = 'ai-typing-indicator';
        
        const dot1 = document.createElement('span');
        const dot2 = document.createElement('span');
        const dot3 = document.createElement('span');
        
        typingDiv.appendChild(dot1);
        typingDiv.appendChild(dot2);
        typingDiv.appendChild(dot3);
        
        chatBody.appendChild(typingDiv);
        
        // Hacer scroll al final del chat
        chatBody.scrollTop = chatBody.scrollHeight;
    }
    
    /**
     * Oculta el indicador de escritura
     */
    function hideTypingIndicator() {
        const typingIndicator = document.getElementById('ai-typing-indicator');
        if (typingIndicator) {
            typingIndicator.remove();
        }
    }
}); 