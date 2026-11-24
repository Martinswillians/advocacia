rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    function isSignedIn() {
      return request.auth != null;
    }

    function isMasterAdmin() {
      return isSignedIn()
        && request.auth.token.email != null
        && request.auth.token.email.lower() == 'willbrasilia@gmail.com';
    }

    function requesterUserPath() {
      return /databases/$(database)/documents/usuarios/$(request.auth.uid);
    }

    function requesterExists() {
      return isSignedIn() && exists(requesterUserPath());
    }

    function requesterData() {
      return get(requesterUserPath()).data;
    }

    function isActiveAccount() {
      return isMasterAdmin() || (
        requesterExists()
        && requesterData().get('accountStatus', 'Ativo') != 'Suspenso'
      );
    }

    function isBoardAdmin() {
      return isMasterAdmin() || (
        isActiveAccount()
        && (
          ('boards' in requesterData() && 'admin' in requesterData().boards)
          || (
            requesterData().get('role', '') == 'responsavel_aab'
            && requesterData().get('promotedByAdmin', false) == true
          )
        )
      );
    }

    function hasPerm(screenId, subKey) {
      return isMasterAdmin() || (
        isActiveAccount()
        && requesterData().get('permissions', {}).get('screens', {}).get(screenId, true) == true
        && requesterData().get('permissions', {}).get('subs', {}).get(subKey, true) == true
      );
    }

    function canPublishMural() {
      return isBoardAdmin() || (
        isActiveAccount()
        && requesterData().get('permissions', {}).get('canPublish', false) == true
      );
    }

    // Perfis de usuários / Webpages dos advogados
    // Leitura liberada para permitir diretório público e webpages individuais de advogados
    match /usuarios/{uid} {
      allow read: if true;

      allow create: if isSignedIn() && (
        request.auth.uid == uid
        || isBoardAdmin()
      );

      allow update: if isSignedIn() && (
        (
          request.auth.uid == uid
          && (!('email' in resource.data) || resource.data.email.lower() != 'willbrasilia@gmail.com' || isMasterAdmin())
          && (
            isBoardAdmin()
            || !request.resource.data.diff(resource.data).affectedKeys().hasAny(['boards', 'role', 'promotedByAdmin', 'accountStatus', 'permissions'])
          )
          && (
            isBoardAdmin()
            || !request.resource.data.diff(resource.data).affectedKeys().hasAny(['name', 'oab', 'firm', 'phone', 'website', 'photoUrl', 'webpage'])
            || hasPerm('profile', 'profile_edit')
          )
        )
        || (
          isBoardAdmin()
          && (!('email' in resource.data) || resource.data.email.lower() != 'willbrasilia@gmail.com' || isMasterAdmin())
        )
      );

      allow delete: if isBoardAdmin()
        && (!('email' in resource.data) || resource.data.email.lower() != 'willbrasilia@gmail.com');

      // Mensagens enviadas por clientes na webpage do advogado (subcoleção)
      match /contatos_webpage/{msgId} {
        allow create: if request.resource.data.keys().hasAll(['clientName', 'clientEmail', 'message'])
          && request.resource.data.clientName is string
          && request.resource.data.clientEmail is string
          && request.resource.data.message is string;
        allow read, update, delete: if isSignedIn() && (request.auth.uid == uid || isBoardAdmin());
      }

      // Subcoleção: Gestão de Processos
      match /processos/{caseId} {
        allow read: if isSignedIn() && request.auth.uid == uid && hasPerm('cases', 'cases_view');
        allow create: if isSignedIn() && request.auth.uid == uid && hasPerm('cases', 'cases_create');
        allow update: if isSignedIn() && request.auth.uid == uid && hasPerm('cases', 'cases_edit');
        allow delete: if isSignedIn() && request.auth.uid == uid && hasPerm('cases', 'cases_delete');
      }

      // Subcoleção: Clientes & CRM
      match /clientes/{clientId} {
        allow read: if isSignedIn() && request.auth.uid == uid && hasPerm('clients', 'clients_view');
        allow create: if isSignedIn() && request.auth.uid == uid && hasPerm('clients', 'clients_create');
        allow update: if isSignedIn() && request.auth.uid == uid && hasPerm('clients', 'clients_edit');
        allow delete: if isSignedIn() && request.auth.uid == uid && hasPerm('clients', 'clients_delete');
      }

      // Subcoleção: Prazos & Agenda
      match /prazos/{deadlineId} {
        allow read: if isSignedIn() && request.auth.uid == uid && hasPerm('deadlines', 'deadlines_view');
        allow create: if isSignedIn() && request.auth.uid == uid && hasPerm('deadlines', 'deadlines_create');
        allow update: if isSignedIn() && request.auth.uid == uid && (
          hasPerm('deadlines', 'deadlines_edit')
          || (
            request.resource.data.diff(resource.data).affectedKeys().hasOnly(['status'])
            && hasPerm('deadlines', 'deadlines_complete')
          )
        );
        allow delete: if isSignedIn() && request.auth.uid == uid && hasPerm('deadlines', 'deadlines_delete');
      }

      // Subcoleção: Financeiro & Honorários
      match /financeiro/{finId} {
        allow read: if isSignedIn() && request.auth.uid == uid && hasPerm('financial', 'financial_view');
        allow create: if isSignedIn() && request.auth.uid == uid && hasPerm('financial', 'financial_create');
        allow update: if isSignedIn() && request.auth.uid == uid && (
          hasPerm('financial', 'financial_edit')
          || (
            request.resource.data.diff(resource.data).affectedKeys().hasOnly(['status'])
            && (
              (request.resource.data.status == 'Pago' && hasPerm('financial', 'financial_confirm_receipt'))
              || (request.resource.data.status != 'Pago' && hasPerm('financial', 'financial_mark_pending'))
            )
          )
        );
        allow delete: if isSignedIn() && request.auth.uid == uid && hasPerm('financial', 'financial_delete');
      }

      // Subcoleção: Reservas de Salas OAB
      match /reservas_salas/{roomId} {
        allow read: if isSignedIn() && request.auth.uid == uid && hasPerm('benefits', 'benefits_reservas');
        allow create, update, delete: if isSignedIn() && request.auth.uid == uid && hasPerm('benefits', 'benefits_salas');
      }
    }

    // Coleção raiz alternativa caso mensagens de contato sejam gravadas em /contatos_webpage
    match /contatos_webpage/{msgId} {
      allow create: if request.resource.data.keys().hasAll(['clientName', 'clientEmail', 'message'])
        && request.resource.data.clientName is string
        && request.resource.data.clientEmail is string
        && request.resource.data.message is string;
      allow read, update, delete: if isSignedIn() && (
        isBoardAdmin()
        || (resource.data.lawyerUid != null && resource.data.lawyerUid == request.auth.uid)
      );
    }

    // Mural Institucional OAB (leitura pública permitida para visitantes)
    match /publicacoes_aab/{bulletinId} {
      allow read: if true;
      allow create, update, delete: if canPublishMural();
    }

    // E-mails previamente autorizados nos quadros
    match /emails_autorizados/{authDocId} {
      allow get: if true;
      allow list: if isSignedIn();
      allow create, update: if isBoardAdmin();
      allow delete: if isBoardAdmin()
        && (!('email' in resource.data) || resource.data.email.lower() != 'willbrasilia@gmail.com');
    }

    // Configurações institucionais
    match /configuracoes/{configId} {
      allow read: if true;
      allow create, update, delete: if isBoardAdmin();
    }
  }
}