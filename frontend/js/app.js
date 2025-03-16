/**
 * Aplicación principal
 */

document.addEventListener('DOMContentLoaded', () => {
    // Elementos del DOM
    const authContainer = document.getElementById('auth-container');
    const appContainer = document.getElementById('app-container');
    const loginTab = document.getElementById('login-tab');
    const registerTab = document.getElementById('register-tab');
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const loginFormEl = document.getElementById('login');
    const registerFormEl = document.getElementById('register');
    const currentUserEl = document.getElementById('current-user');
    const logoutBtn = document.getElementById('logout-btn');
    const usersTab = document.getElementById('users-tab');
    const receivedTab = document.getElementById('received-tab');
    const sentTab = document.getElementById('sent-tab');
    const usersList = document.getElementById('users-list');
    const receivedList = document.getElementById('received-list');
    const sentList = document.getElementById('sent-list');
    const userListEl = document.getElementById('users');
    const receivedMessagesEl = document.getElementById('received-messages');
    const sentMessagesEl = document.getElementById('sent-messages');
    const messageComposeEl = document.getElementById('message-compose');
    const messageViewEl = document.getElementById('message-view');
    const composeFormEl = document.getElementById('compose-form');
    const recipientSelectEl = document.getElementById('recipient');
    const messageContentEl = document.getElementById('message-content');
    const expiresEl = document.getElementById('expires');
    const messageTitleEl = document.getElementById('message-title');
    const messageSenderEl = document.getElementById('message-sender');
    const messageRecipientEl = document.getElementById('message-recipient');
    const messageDateEl = document.getElementById('message-date');
    const messageExpiresContainerEl = document.getElementById('message-expires-container');
    const messageExpiresEl = document.getElementById('message-expires');
    const messageEncryptedEl = document.getElementById('message-encrypted');
    const messageDecryptedEl = document.getElementById('message-decrypted');
    const decryptPasswordEl = document.getElementById('decrypt-password');
    const decryptBtnEl = document.getElementById('decrypt-btn');
    const decryptedContentEl = document.getElementById('decrypted-content');
    const backBtnEl = document.getElementById('back-btn');
    const notificationEl = document.getElementById('notification');
    
    // Función para mostrar notificaciones
    function showNotification(message, type = 'info') {
        notificationEl.textContent = message;
        notificationEl.className = `notification ${type} show`;
        
        setTimeout(() => {
            notificationEl.className = 'notification hidden';
        }, 3000);
    }
    
    // Función para cambiar entre las pestañas de autenticación
    function switchAuthTab(tab) {
        if (tab === 'login') {
            loginTab.classList.add('active');
            registerTab.classList.remove('active');
            loginForm.classList.remove('hidden');
            registerForm.classList.add('hidden');
        } else {
            loginTab.classList.remove('active');
            registerTab.classList.add('active');
            loginForm.classList.add('hidden');
            registerForm.classList.remove('hidden');
        }
    }
    
    // Función para cambiar entre las pestañas de la aplicación
    function switchAppTab(tab) {
        usersTab.classList.remove('active');
        receivedTab.classList.remove('active');
        sentTab.classList.remove('active');
        usersList.classList.add('hidden');
        receivedList.classList.add('hidden');
        sentList.classList.add('hidden');
        
        if (tab === 'users') {
            usersTab.classList.add('active');
            usersList.classList.remove('hidden');
        } else if (tab === 'received') {
            receivedTab.classList.add('active');
            receivedList.classList.remove('hidden');
        } else if (tab === 'sent') {
            sentTab.classList.add('active');
            sentList.classList.remove('hidden');
        }
    }
    
    // Función para mostrar la vista de composición de mensajes
    function showComposeView() {
        messageComposeEl.classList.remove('hidden');
        messageViewEl.classList.add('hidden');
    }
    
    // Función para mostrar la vista de un mensaje
    function showMessageView() {
        messageComposeEl.classList.add('hidden');
        messageViewEl.classList.remove('hidden');
        messageEncryptedEl.classList.remove('hidden');
        messageDecryptedEl.classList.add('hidden');
    }
    
    // Función para cargar la lista de usuarios
    async function loadUsers() {
        try {
            await Messages.loadUsers();
            
            // Limpiar la lista de usuarios
            userListEl.innerHTML = '';
            recipientSelectEl.innerHTML = '<option value="">Selecciona un destinatario</option>';
            
            // Agregar los usuarios a la lista
            Messages.users.forEach(user => {
                // No mostrar al usuario actual en la lista
                if (user.id === Auth.getUser().id) return;
                
                const li = document.createElement('li');
                li.textContent = user.username;
                li.dataset.userId = user.id;
                li.addEventListener('click', () => {
                    // Seleccionar al usuario como destinatario
                    recipientSelectEl.value = user.id;
                    showComposeView();
                });
                userListEl.appendChild(li);
                
                // Agregar el usuario al select de destinatarios
                const option = document.createElement('option');
                option.value = user.id;
                option.textContent = user.username;
                recipientSelectEl.appendChild(option);
            });
        } catch (error) {
            showNotification(`Error al cargar usuarios: ${error.message}`, 'error');
        }
    }
    
    // Función para cargar los mensajes recibidos
    async function loadReceivedMessages() {
        try {
            await Messages.loadReceivedMessages();
            
            // Limpiar la lista de mensajes recibidos
            receivedMessagesEl.innerHTML = '';
            
            // Agregar los mensajes recibidos a la lista
            Messages.receivedMessages.forEach(message => {
                const li = document.createElement('li');
                li.textContent = `De: ${Messages.getUsernameById(message.sender_id)} - ${Messages.formatDate(message.created_at)}`;
                li.dataset.messageId = message.id;
                
                // Marcar los mensajes no leídos
                if (!message.is_read) {
                    li.classList.add('unread');
                }
                
                li.addEventListener('click', () => {
                    // Mostrar el mensaje
                    showMessage(message.id);
                });
                
                receivedMessagesEl.appendChild(li);
            });
        } catch (error) {
            showNotification(`Error al cargar mensajes recibidos: ${error.message}`, 'error');
        }
    }
    
    // Función para cargar los mensajes enviados
    async function loadSentMessages() {
        try {
            await Messages.loadSentMessages();
            
            // Limpiar la lista de mensajes enviados
            sentMessagesEl.innerHTML = '';
            
            // Agregar los mensajes enviados a la lista
            Messages.sentMessages.forEach(message => {
                const li = document.createElement('li');
                li.textContent = `Para: ${Messages.getUsernameById(message.recipient_id)} - ${Messages.formatDate(message.created_at)}`;
                li.dataset.messageId = message.id;
                
                li.addEventListener('click', () => {
                    // Mostrar el mensaje
                    showMessage(message.id);
                });
                
                sentMessagesEl.appendChild(li);
            });
        } catch (error) {
            showNotification(`Error al cargar mensajes enviados: ${error.message}`, 'error');
        }
    }
    
    // Función para mostrar un mensaje
    async function showMessage(messageId) {
        try {
            // Obtener el mensaje de la lista de mensajes
            let message = Messages.receivedMessages.find(m => m.id === messageId);
            if (!message) {
                message = Messages.sentMessages.find(m => m.id === messageId);
            }
            
            if (!message) {
                showNotification('Mensaje no encontrado', 'error');
                return;
            }
            
            // Mostrar la vista de mensaje
            showMessageView();
            
            // Actualizar la información del mensaje
            messageTitleEl.textContent = 'Mensaje';
            messageSenderEl.textContent = Messages.getUsernameById(message.sender_id);
            messageRecipientEl.textContent = Messages.getUsernameById(message.recipient_id);
            messageDateEl.textContent = Messages.formatDate(message.created_at);
            
            // Mostrar la fecha de caducidad si existe
            if (message.expires_at) {
                messageExpiresContainerEl.classList.remove('hidden');
                messageExpiresEl.textContent = Messages.formatDate(message.expires_at);
            } else {
                messageExpiresContainerEl.classList.add('hidden');
            }
            
            // Guardar el ID del mensaje actual
            messageViewEl.dataset.messageId = messageId;
        } catch (error) {
            showNotification(`Error al mostrar mensaje: ${error.message}`, 'error');
        }
    }
    
    // Función para descifrar un mensaje
    async function decryptMessage(messageId, password) {
        try {
            const message = await Messages.getMessage(messageId, password);
            
            // Mostrar el contenido descifrado
            messageEncryptedEl.classList.add('hidden');
            messageDecryptedEl.classList.remove('hidden');
            decryptedContentEl.textContent = message.content;
            
            showNotification('Mensaje descifrado correctamente', 'success');
        } catch (error) {
            showNotification(`Error al descifrar mensaje: ${error.message}`, 'error');
        }
    }
    
    // Función para inicializar la aplicación
    function initApp() {
        // Verificar si hay una sesión activa
        if (Auth.isAuthenticated()) {
            // Mostrar la aplicación
            authContainer.classList.add('hidden');
            appContainer.classList.remove('hidden');
            
            // Mostrar el nombre de usuario
            const user = Auth.getUser();
            currentUserEl.textContent = `Usuario: ${user.username}`;
            
            // Cargar los datos iniciales
            loadUsers();
            loadReceivedMessages();
            loadSentMessages();
            
            // Mostrar la vista de composición de mensajes
            showComposeView();
        } else {
            // Mostrar el formulario de autenticación
            authContainer.classList.remove('hidden');
            appContainer.classList.add('hidden');
            
            // Mostrar la pestaña de inicio de sesión
            switchAuthTab('login');
        }
    }
    
    // Event listeners para las pestañas de autenticación
    loginTab.addEventListener('click', () => switchAuthTab('login'));
    registerTab.addEventListener('click', () => switchAuthTab('register'));
    
    // Event listener para el formulario de inicio de sesión
    loginFormEl.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;
        
        try {
            await Auth.login(username, password);
            showNotification('Sesión iniciada correctamente', 'success');
            initApp();
        } catch (error) {
            showNotification(`Error al iniciar sesión: ${error.message}`, 'error');
        }
    });
    
    // Event listener para el formulario de registro
    registerFormEl.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = document.getElementById('register-username').value;
        const email = document.getElementById('register-email').value;
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('register-confirm-password').value;
        
        // Verificar que las contraseñas coincidan
        if (password !== confirmPassword) {
            showNotification('Las contraseñas no coinciden', 'error');
            return;
        }
        
        try {
            await Auth.register(username, email, password);
            showNotification('Usuario registrado correctamente', 'success');
            initApp();
        } catch (error) {
            showNotification(`Error al registrar usuario: ${error.message}`, 'error');
        }
    });
    
    // Event listener para el botón de cerrar sesión
    logoutBtn.addEventListener('click', () => {
        Auth.logout();
        showNotification('Sesión cerrada correctamente', 'success');
        initApp();
    });
    
    // Event listeners para las pestañas de la aplicación
    usersTab.addEventListener('click', () => switchAppTab('users'));
    receivedTab.addEventListener('click', () => switchAppTab('received'));
    sentTab.addEventListener('click', () => switchAppTab('sent'));
    
    // Event listener para el formulario de envío de mensajes
    composeFormEl.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const recipientId = parseInt(recipientSelectEl.value);
        const content = messageContentEl.value;
        const expiresInHours = expiresEl.value ? parseInt(expiresEl.value) : null;
        const password = document.getElementById('send-password').value;
        
        if (!password) {
            showNotification('Debes ingresar tu contraseña para firmar el mensaje', 'error');
            return;
        }
        
        try {
            await Messages.sendMessage(recipientId, content, expiresInHours, password);
            
            // Limpiar el formulario
            composeFormEl.reset();
            
            showNotification('Mensaje enviado correctamente', 'success');
            
            // Actualizar la lista de mensajes enviados
            loadSentMessages();
            
            // Cambiar a la pestaña de mensajes enviados
            switchAppTab('sent');
        } catch (error) {
            showNotification(`Error al enviar mensaje: ${error.message}`, 'error');
        }
    });
    
    // Event listener para el botón de descifrar
    decryptBtnEl.addEventListener('click', () => {
        const messageId = parseInt(messageViewEl.dataset.messageId);
        const password = decryptPasswordEl.value;
        
        if (!password) {
            showNotification('Debes ingresar tu contraseña para descifrar el mensaje', 'error');
            return;
        }
        
        decryptMessage(messageId, password);
    });
    
    // Event listener para el botón de volver
    backBtnEl.addEventListener('click', () => {
        showComposeView();
    });
    
    // Inicializar la aplicación
    initApp();
}); 