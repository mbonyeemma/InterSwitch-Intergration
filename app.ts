import express, { Request, Response } from 'express';
import ISW from './isw';

class App {
    private app: express.Express;
    private iswInstance: ISW;

    constructor() {
        this.app = express();
        this.app.use(express.json());
        this.iswInstance = new ISW();
        this.initializeRoutes();
    }



    private initializeRoutes(): void {
        this.app.post('/validateCustomer', this.validateCustomer.bind(this));
        this.app.post('/categories-by-client', this.getBillerCategories.bind(this));
        this.app.get('/getcategoryBillers', this.getCategoryBillers.bind(this));
        this.app.post('/items', this.getPaymentItems.bind(this));
        this.app.post('/payment', this.payment.bind(this));
        this.app.post('/transStatus/:terminalId/:requestReference', this.transStatus.bind(this));
        this.app.post('/accountBalance', this.accountBalance.bind(this));
        this.app.get('/keyPair', this.generateRSAKeyPair.bind(this));
        this.app.post('/clientRegistration', this.clientRegistration.bind(this));
        this.app.post('/doKeyExchange', this.doKeyExchange.bind(this));
        this.app.get('/generateECDHKeyPair', this.generateECDHKeyPair.bind(this));
        this.app.get('/util', this.util.bind(this));

    }

   
    async util(req: Request, res: Response) {
        try {
            var clSec = 'EakZ68Q9Ij6gB3ipIty7SSidnjbRsNeDC0BEWEXrEf7Q/BybAFcXg06UluC6gqJO440AZn2jph+rFrwxUWyVMRGXWK7d7GglsO7e7rlvPdHOSkJUh819BgHQbkFDrIF9sTnNlXdxOq4JX30GiEb6sJ2leb+bjtUXy2uqB5I2o1PxCTHMzsGg3H7POBc+4hDaBbKq4GoVZo5XEZdGf5R5nPsG+3Q4ebkLy/t+ldf4QuCrl8wfcx4yqHBg578FSzQ5CmaP+IRIpo+UsJZLP4FjKPo0pUZxWvVPf156Wjk+5H5chvVW4itmr8Igm/jcch8773yChDOdtJ4X/BDjodAmFQ=='

            const responseData = this.iswInstance.decryptWithPrivateKey(clSec);
            console.log("certificate", responseData)
            res.send(responseData);
        } catch (error) {
            res.status(500).send(error);
        }
    }
    
    async generateECDHKeyPair(req: Request, res: Response) {
        try {
            const responseData = this.iswInstance.generateECDHKeyPair();
            console.log("certificate", responseData)
            res.send(responseData);
        } catch (error) {
            res.status(500).send(error);
        }
    }

    async doKeyExchange(req: Request, res: Response) {
        try {
            const responseData = this.iswInstance.doKeyExchange();
            console.log("certificate", responseData)
            res.send(responseData);
        } catch (error) {
            res.status(500).send(error);
        }
    }

    async generateRSAKeyPair(req: Request, res: Response) {
        try {
            const responseData = this.iswInstance.generateRSAKeyPair();
            console.log("certificate", responseData)
            res.send(responseData);
        } catch (error) {
            res.status(500).send(error);
        }
    }



    async accountBalance(req: Request, res: Response) {
        try {
            const responseData = await this.iswInstance.accountBalance(req.body);
            res.send(responseData);
        } catch (error) {
            res.status(500).send(error);
        }
    }
    async clientRegistration(req: Request, res: Response) {
        try {
            const responseData = await this.iswInstance.clientRegistration(req.body);
            res.send(responseData);
        } catch (error) {
            res.status(500).send(error);
        }
    }



    async transStatus(req: Request, res: Response) {
        try {
            const responseData = await this.iswInstance.transactionInformation(req.body);
            res.send(responseData);
        } catch (error) {
            res.status(500).send(error);
        }
    }

    async validateCustomer(req: Request, res: Response) {
        try {
            const responseData = await this.iswInstance.validateCustomer(req.body);
            res.send(responseData);
        } catch (error) {
            res.status(500).send(error);
        }
    }

    async getBillerCategories(req: Request, res: Response) {
        try {
            const responseData = await this.iswInstance.Getcategories();
            res.send(responseData);
        } catch (error) {
            res.status(500).send(error);
        }
    }

    async getCategoryBillers(req: Request, res: Response) {
        try {
            const responseData = await this.iswInstance.Getcategories();
            res.send(responseData);
        } catch (error) {
            res.status(500).send(error);
        }
    }

    async getPaymentItems(req: Request, res: Response) {
        try {
            const responseData = await this.iswInstance.GetPaymentItems(req.body);
            res.send(responseData);
        } catch (error) {
            res.status(500).send(error);
        }
    }

    async payment(req: Request, res: Response) {
        try {
            const responseData = await this.iswInstance.makePayment(req.body);
            res.send(responseData);
        } catch (error) {
            res.status(500).send(error);
        }
    }

    startServer(port: any) {
        this.app.listen(port, () => {
            console.log(`Server is running on http://localhost:${port}`);
        });
    }
}

const appInstance = new App();
appInstance.startServer(3000);
