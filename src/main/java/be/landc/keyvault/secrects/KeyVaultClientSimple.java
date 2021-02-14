package be.landc.keyvault.secrects;

import java.time.OffsetDateTime;

import com.azure.core.util.polling.PollResponse;
import com.azure.core.util.polling.SyncPoller;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.DeletedSecret;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import com.azure.identity.DefaultAzureCredentialBuilder;

/**
 * Sample demonstrates how to set, get, update and delete a secret.
 */
public class KeyVaultClientSimple {

	/**
	 * Authenticates with the key vault and shows how to set, get, update and delete
	 * a secret in the key vault.
	 *
	 * @param args Unused. Arguments to the program.
	 * @throws IllegalArgumentException when invalid key vault endpoint is passed.
	 * @throws InterruptedException     when the thread is interrupted in sleep
	 *                                  mode.
	 */
	public static void main(String[] args) throws InterruptedException, IllegalArgumentException {

		/*
		 * 1. First create a service principal in AZ AD 2. Add a client secret to it
		 * 3.Add this service principal to azue keyvault access policies 4.Instantiate a
		 * secret client that will be used to call the service. Notice that the client
		 * is using default Azure credentials. To make default credentials work, ensure
		 * that environment variables 'AZURE_CLIENT_ID', 'AZURE_CLIENT_KEY' and
		 * 'AZURE_TENANT_ID' are set with the service principal credentials.
		 */

		SecretClient secretClient = new SecretClientBuilder().vaultUrl("https://pramitkeyvault.vault.azure.net/")
				.credential(new DefaultAzureCredentialBuilder().build()).buildClient();

		// Let's create a secret holding bank account credentials valid for 1 year. if
		// the secret
		// already exists in the key vault, then a new version of the secret is created.
		secretClient.setSecret(new KeyVaultSecret("BankAccountSecret", "f4G34fMh8v")
				.setProperties(new SecretProperties().setExpiresOn(OffsetDateTime.now().plusYears(1))));

		// Let's Get the bank secret from the key vault.
		KeyVaultSecret bankSecret = secretClient.getSecret("BankAccountSecret");
		System.out.printf("Secret is returned with name %s and value %s \n", bankSecret.getName(),
				bankSecret.getValue());

		// List operations don't return the secrets with value information. So, for each
		// returned secret we call getSecret to
		// get the secret with its value information.
		for (SecretProperties secretProperties : secretClient.listPropertiesOfSecrets()) {
			KeyVaultSecret secretWithValue = secretClient.getSecret(secretProperties.getName(),
					secretProperties.getVersion());
			System.out.printf("Retrieved secret with name \"%s\" and value \"%s\"%n", secretWithValue.getName(),
					secretWithValue.getValue());
		}

		// After one year, the bank account is still active, we need to update the
		// expiry time of the secret.
		// The update method can be used to update the expiry attribute of the secret.
		// It cannot be used to update
		// the value of the secret.
		bankSecret.getProperties().setExpiresOn(OffsetDateTime.now().plusYears(1));
		SecretProperties updatedSecret = secretClient.updateSecretProperties(bankSecret.getProperties());
		System.out.printf("Secret's updated expiry time %s \n", updatedSecret.getExpiresOn());

		// Bank forced a password update for security purposes. Let's change the value
		// of the secret in the key vault.
		// To achieve this, we need to create a new version of the secret in the key
		// vault. The update operation cannot
		// change the value of the secret.
		secretClient.setSecret(new KeyVaultSecret("BankAccountSecret", "bhjd4DDgsa")
				.setProperties(new SecretProperties().setExpiresOn(OffsetDateTime.now().plusYears(1))));

		// The bank account was closed, need to delete its credentials from the key
		// vault.
		SyncPoller<DeletedSecret, Void> deletedBankSecretPoller = secretClient.beginDeleteSecret("BankAccountSecret");

		PollResponse<DeletedSecret> deletedBankSecretPollResponse = deletedBankSecretPoller.poll();

		System.out.println("Deleted Date %s" + deletedBankSecretPollResponse.getValue().getDeletedOn().toString());
		System.out.printf("Deleted Secret's Recovery Id %s", deletedBankSecretPollResponse.getValue().getRecoveryId());

		// Key is being deleted on server.
		deletedBankSecretPoller.waitForCompletion();

		// If the key vault is soft-delete enabled, then for permanent deletion deleted
		// secrets need to be purged.
		secretClient.purgeDeletedSecret("BankAccountSecret");
	}
}