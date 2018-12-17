# Specification
In the interest of organization and consistency, this specification will inform the structure of the library.


## **Analyzer**

### _Definition_
An `Analyzer` defines a method of scoring text according to some standard.

### _Functions_

#### analyze
Takes in an array of bytes and outputs a score. The higher the score, the greater the fitness.


## **Primitive**

### _Definition_
A `Primitive` defines a cryptographic building block. Currently, this encapsulates a large portion of the hierarchy.



## **Oracle**

### _Definition_
An `Oracle` defines an interaction with a system that leaks some information.



## **Attack**

### _Definition_
An `Attack` defines a specific method of breaking a system and sit at the top of the hierarchy. `Attacks` can be online or offline.

### _Functions_

#### init
The initialization of an `Attack` should only contain the parameters needed to configure the execution to work with a system.

#### execute
`execute` initiates the attack and may take data as a parameter.

Since the execution of an attack generally involves many moving parts and some user-defined execution, logging should be included within each module that keeps internal state over several iterations.