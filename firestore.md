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

    function isBoardAdmin() {
      return isMasterAdmin() || (
        requesterExists()
        && requesterData().get('accountStatus', 'Ativo') != 'Suspenso'
        && (
          ('boards' in requesterData() && 'admin' in requesterData().boards)
          || (
            requesterData().get('role', '') == 'responsavel_aab'
            && requesterData().get('promotedByAdmin', false) == true
          )
        )
      );
    }

    function canPublishMural() {
      return isBoardAdmin() || (
        requesterExists()
        && requesterData().get('accountStatus', 'Ativo') != 'Suspenso'
        && requesterData().get('permissions', {}).get('canPublish', false) == true
      );
    }

    // Perfis de usuários (Associados e Administradores)
    match /usuarios/{uid} {
      allow read: if isSignedIn();

      allow create: if isSignedIn() && (
        request.auth.uid == uid
        || isBoardAdmin()
      );

      allow update: if isSignedIn() && (
        (
          request.auth.uid == uid
          && (!('email' in resource.data) || resource.data.email.lower() != 'willbrasilia@gmail.com' || isMasterAdmin())
        )
        || (
          isBoardAdmin()
          && (!('email' in resource.data) || resource.data.email.lower() != 'willbrasilia@gmail.com' || isMasterAdmin())
        )
      );

      allow delete: if isBoardAdmin()
        && (!('email' in resource.data) || resource.data.email.lower() != 'willbrasilia@gmail.com');

      // Subcoleções privativas do escritório do associado/administrador
      match /processos/{caseId} {
        allow read, write: if isSignedIn() && request.auth.uid == uid;
      }
      match /clientes/{clientId} {
        allow read, write: if isSignedIn() && request.auth.uid == uid;
      }
      match /prazos/{deadlineId} {
        allow read, write: if isSignedIn() && request.auth.uid == uid;
      }
      match /financeiro/{finId} {
        allow read, write: if isSignedIn() && request.auth.uid == uid;
      }
      match /reservas_salas/{roomId} {
        allow read, write: if isSignedIn() && request.auth.uid == uid;
      }
    }

    // Mural Institucional AAB
    match /publicacoes_aab/{bulletinId} {
      allow read: if isSignedIn();
      allow create, update, delete: if canPublishMural();
    }

    // E-mails previamente autorizados nos quadros (Quadro Adm / Quadro Associados)
    match /emails_autorizados/{authDocId} {
      allow get: if true;
      allow list: if isSignedIn();
      allow create, update: if isBoardAdmin();
      allow delete: if isBoardAdmin()
        && (!('email' in resource.data) || resource.data.email.lower() != 'willbrasilia@gmail.com');
    }

    // Configurações institucionais (links de benefícios)
    match /configuracoes/{configId} {
      allow read: if isSignedIn();
      allow create, update, delete: if isBoardAdmin();
    }
  }
}