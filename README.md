In this project I have designed a login, signup and forgot-password system for a web portal. I have also added it to the mongoDB database from where it fetches the saved
information of the user using logging in after signup. The info is Bycrypted at the time of storage in the databases and fetched using keys. I've used nodeJS for 
sending mail to the user for forgot-password option. It automatically sends a mail to the user with the ID from which the user has signed in. All the user has to do 
is click on the link and set a new password for his/her account and it automatically gets updated in the database as well. For the authentication purpose I've used Google OAuth2 
which verifies the account information using the database.
