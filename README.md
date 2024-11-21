🎯 This repository provides examples and best practices for understanding and preventing SQL Injection.  

# SQL-INJECTION
**SQL Injection** is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It typically occurs when user input is improperly sanitized or validated, enabling malicious SQL statements to be executed.

---

# 🛡️ SQL Injection: Types and Mitigation  

**SQL Injection** is a critical web security vulnerability that allows attackers to interfere with database queries. This document outlines the types of SQL Injection attacks and how to prevent them.

---

## 📋 Table of Contents
1. [🚨 Types of SQL Injection](#types-of-sql-injection)  
   - [In-Band SQL Injection](#in-band-sql-injection)  
     - [Error-Based Injection](#error-based-injection)  
     - [Union-Based Injection](#union-based-injection)  
   - [Blind SQL Injection](#blind-sql-injection)  
     - [Boolean-Based Blind Injection](#boolean-based-blind-injection)  
     - [Time-Based Blind Injection](#time-based-blind-injection)  
   - [Out-of-Band SQL Injection](#out-of-band-sql-injection)  
   - [Second-Order SQL Injection](#second-order-sql-injection)  
   - [Stored Persistent SQL Injection](#stored-persistent-sql-injection)  
2. [🛡️ Mitigation Strategies](#mitigation-strategies)  


---
### Important Considerations Before Exploring SQL Injection Types

Before diving into the different types of *SQL Injection*, it's essential to first identify the type of database you're dealing with. For example, when working with an **Oracle** database, understanding its specific syntax and quirks is crucial, such as how to write queries and use comments correctly.

#### Useful Reference:
For a comprehensive SQL Injection cheat sheet, check out this great resource from PortSwigger:  
[SQL Injection Cheat Sheet - PortSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)


---
# 🚨 Types of SQL Injection    

## In-Band SQL Injection  
- It occurs when the attacker uses the same communication channel to inject malicious SQL code.
   

### Error-Based Injection  
- Exploits database error messages to extract data.
- In **Error-Based SQL Injection**, the key point is that you receive an error message from the database you are dealing with.  

  If you attempt to inject SQL code into the database and receive an error message directly from the database, it indicates that the database is          **vulnerable** to Error-Based SQL Injection.

<hr style="border: 0.1px">

### Union-Based Injection  
- Uses the `UNION` operator to combine and retrieve data from multiple tables.
   #### How to Prove the Concept of a Vulnerable Application Database with *Union-Based* Injection

  To prove that an application database is vulnerable to *Union-Based* SQL Injection, follow these steps:

   1. **Identify the number of columns in the database** by injecting the following SQL code:
    ```sql
    ' UNION SELECT NULL -- 
    ```

   2. If the above query doesn't work, try adding more columns to match the number expected by the query:
       ```sql
       ' UNION SELECT NULL, NULL -- 
       ```

   Keep adding columns (e.g., `NULL, NULL, NULL --`) until you identify the correct number of columns that the query expects.

#### Real Example from PortSwigger

In this example, I attempted to inject SQL code into the application to test for a vulnerability.

#### First Injection
   ```sql
     ' UNION SELECT NULL-- 
   ```
![image](https://github.com/user-attachments/assets/234954be-999d-4bda-b9c8-cf689968c6e1)

 However, I received an Internal Server Error as a result.
 
   ![image](https://github.com/user-attachments/assets/b3ca285a-8028-41de-b43b-e811342ecbfe)
   
 #### Second Injection
   ```sql
      ' UNION SELECT NULL#
   ```

 ![image](https://github.com/user-attachments/assets/ca8e4157-4b96-45e9-9b40-608fcfc2a402)

 As well this not working and we will keep trying:
 ![image](https://github.com/user-attachments/assets/03459deb-cd7d-4f62-9cb9-4325a742ab5b)

 #### Third Injection:
  ```sql
      ' UNION SELECT NULL#
   ```

![image](https://github.com/user-attachments/assets/7dd060c8-59f5-4205-8ec9-874cd8f47936)

  After this injection, I received a **200 OK** response, and the page interacted with the injected SQL code. This indicates that the application is **vulnerable** to SQL Injection.
```sql
      ' UNION SELECT NULL,NULL--
   ```

![image](https://github.com/user-attachments/assets/8d091b5b-e01d-48ab-8d14-9dbe45e3d7e4)

    
Now, we can inject this SQL code to know what is the version of the database.

  ```sql
      ' UNION SELECT version(),NULL--
   ```
![image](https://github.com/user-attachments/assets/431c8ab3-7fec-4073-b62c-b358ed2af01c)




This is great and valuable information, as now we know how to deal with this database.


If you know the database is injectable, you understand how many columns it has, and you know the database version, you have almost gathered all the essential information and knowledge about the application you're testing.

You can practice and deep dive into **UNION SQL Injection** by visiting [PortSwigger](https://portswigger.net) and practicing on their labs.



---
## Blind SQL Injection  

#### Boolean-Based Blind Injection  
- Sends queries that return true/false and observes application behavior.  

#### Time-Based Blind Injection  
- Uses queries that trigger time delays to infer responses.  

### Out-of-Band SQL Injection  
- Relies on a separate communication channel (e.g., DNS or HTTP) for data retrieval, often used when in-band methods are unavailable.  

### Second-Order SQL Injection  
- Malicious input is stored in the database and executed later when retrieved by the application.  

### Stored Persistent SQL Injection  
- Payload is saved in the database (e.g., via forms) and executed when data is displayed, affecting all users.  


---

## 🛡️ Mitigation Strategies  

- Use **parameterized queries** or **prepared statements**.  
- Sanitize and validate all user inputs.  
- Avoid displaying detailed database error messages in production.  
- Employ the **principle of least privilege** for database users.  
- Conduct regular security audits and penetration testing.  
