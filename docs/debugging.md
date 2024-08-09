## Unable to login using the client

If you're getting an `XMO_AUTHENTICATION_ERR` from your device when trying to log in, it may be that your device is expecting a "salt" to be chained to the password.
To check if that is the case, use your browser to navigate to your device's login page. Then, evaluate the following expression in your browser's debug console:

```
jQuery.gui.opt.GUI_PASSWORD_SALT
```

In the following example, the salt seems to be "Salt123":

![image](https://github.com/user-attachments/assets/f60f4633-cbb6-4e8f-a674-0d7f3cda0ab2)


You can then log in using by using the password `<original password>:Salt123`. For example:

```python
async with SagemcomClient(HOST, USERNAME, "myPassword:Salt123", ENCRYPTION_METHOD) as client:
    try:
        await client.login()
    except Exception as exception:  # pylint: disable=broad-except
        print(exception)
```
