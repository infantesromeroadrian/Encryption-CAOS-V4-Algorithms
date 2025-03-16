/**
 * Módulo para la gestión de mensajes
 */

const Messages = {
    // Almacenamiento local de mensajes
    receivedMessages: [],
    sentMessages: [],
    users: [],
    currentMessage: null,
    
    // Cargar los usuarios
    async loadUsers() {
        try {
            const token = Auth.getToken();
            if (!token) return;
            
            this.users = await API.users.list(token);
            return this.users;
        } catch (error) {
            console.error('Error al cargar usuarios:', error);
            throw error;
        }
    },
    
    // Cargar los mensajes recibidos
    async loadReceivedMessages() {
        try {
            const token = Auth.getToken();
            if (!token) return;
            
            this.receivedMessages = await API.messages.received(token);
            return this.receivedMessages;
        } catch (error) {
            console.error('Error al cargar mensajes recibidos:', error);
            throw error;
        }
    },
    
    // Cargar los mensajes enviados
    async loadSentMessages() {
        try {
            const token = Auth.getToken();
            if (!token) return;
            
            this.sentMessages = await API.messages.sent(token);
            return this.sentMessages;
        } catch (error) {
            console.error('Error al cargar mensajes enviados:', error);
            throw error;
        }
    },
    
    // Enviar un mensaje
    async sendMessage(recipientId, content, expiresInHours, password) {
        try {
            const token = Auth.getToken();
            if (!token) throw new Error('No hay sesión activa');
            
            const message = await API.messages.send(recipientId, content, expiresInHours, password, token);
            
            // Actualizar la lista de mensajes enviados
            await this.loadSentMessages();
            
            return message;
        } catch (error) {
            console.error('Error al enviar mensaje:', error);
            throw error;
        }
    },
    
    // Obtener un mensaje por su ID
    async getMessage(messageId, password) {
        try {
            const token = Auth.getToken();
            if (!token) throw new Error('No hay sesión activa');
            
            const message = await API.messages.get(messageId, password, token);
            this.currentMessage = message;
            
            return message;
        } catch (error) {
            console.error('Error al obtener mensaje:', error);
            throw error;
        }
    },
    
    // Formatear la fecha
    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleString();
    },
    
    // Obtener el nombre de usuario por ID
    getUsernameById(userId) {
        const user = this.users.find(user => user.id === userId);
        return user ? user.username : 'Usuario desconocido';
    }
}; 