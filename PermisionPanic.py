import argparse
from utils.configuration import Configuration 
from pyfiglet import Figlet

def parse_arguments():
    parser = argparse.ArgumentParser(description='PermissionPanic CLI Tool')
    
    # Add argument for specifying the configuration file (-f or --file)
    parser.add_argument('-f', '--file', type=str, required=True,
                        help='Path to the configuration file')

    # Add argument for specifying the output (-o or --output)
    parser.add_argument('-o', '--output', type=str, choices=['csv','json','stdout'],
                        default='stdout', help='Output stream (defult is stdout)')
    
    return parser.parse_args()



def banner():
    custom_fig = Figlet(font='Fender')
    print(custom_fig.renderText('PermissionPanic'))
    custom_fig = Figlet(font='Digital')
    print(custom_fig.renderText('Adi Malyanker'))
    print(custom_fig.renderText('Shay Reuven'))



args = parse_arguments()
banner()
conf = Configuration(filename=args.file).get_config()

from utils import logger

logger = logger.createLogger('main')
logger.info(f'load configuration from: {args.file}')
logger.info(f'log level set to: {conf["logLevel"]}')


from attacks.attack_controller import AttackController
from utils import azure_utils
from AppRW import ApplicationRW_Vectors

import pandas as pd


def start_attack():
    config = Configuration().get_config()
    logger.info('create tokens each application')
    apps = create_tokens(config["tenants"],'https://graph.microsoft.com')
    logger.info('start searching for vector attacks...')

    vector_df = pd.DataFrame()
    for app in apps:
        attackController = AttackController(app)
        attackController.run_attacks()
        vector_df = pd.concat([vector_df, attackController.get_responses_df()], ignore_index=True) 

    df = vector_df[vector_df['Status'] == True]
    return df


def create_tokens(tenants,resourceURL):
    tokens = []
    for tenant in tenants:
        tenantId = tenant["tenantId"]
        for application in tenant["applications"]:
            appId = list(application.keys())[0]
            secret = application[appId]
            accessToken = azure_utils.getTokenByCred(tenantId,appId,secret, resourceURL)
            roles = azure_utils.getPermissionByToken(accessToken)
            tokens.append({"tenantId": tenantId ,"appId": appId, "roles": roles, "token": accessToken })

    return tokens

def handle_output(output,type):
    if type == "csv":
        output.to_csv('output.csv', index=False)
    elif type == "json":
        output.to_json('output.json', orient='records')
    else:
        print()
        print(output)


def main(args):
    output = start_attack()
    handle_output(output,args.output)


if __name__ == "__main__":
    main(args)
