
# IMPORT LIBRARIES # # # # # # # # # # # # # # # # # # # # # # # # #
import os
import sys
from hashlib import sha256
from sqlalchemy import create_engine
from sqlalchemy import Column, ForeignKey, Integer, String, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
# Creating the base class - to be used to define any number of
# mapped classes (tables):
Base = declarative_base()

# MAP DATABASE OBJECTS TO PYTHON CLASSES # # # # # # # # # # # # # #

# Setting up one-to-many relationships:
#
# 1) Specify 'relationship' on the parent referencing a collection of 
#    items represented by the child.
# 2) Place a foreign key on the child table referencing the parent.

# Enable cascading:
#
# 'cascade' option determines how operations performed on the parent 
# (most interestingly 'delete' operations) propagate to child items.
# It's best to always set the 'cascade' option to 'all, delete-orphan'.
# The 'all' is a synonym for save-update, merge, refresh-expire, expunge,
# delete, and using it in conjunction with 'delete-orphan' indicates that
# the child object should follow along with its parent in all cases,
# and be deleted once it is no longer associated with the parent

class User(Base):
	__tablename__ = 'user'
	id = Column(Integer, primary_key=True)
	name = Column(String(250), nullable=False)
	password = Column(String(64), nullable=False)
	salt = Column(String(45), nullable=False)
	email = Column(String(250), nullable=False)
	periods = relationship('Period', cascade='all, delete-orphan')

	def check_password(self, password):
		salted_password = self.salt + password
		hashed_password = sha256(salted_password).hexdigest()
		if self.password == hashed_password:
			return True
		else:
			return False

class Period(Base):
	__tablename__ = 'period'
	id = Column(Integer, primary_key=True) 
	user_id = Column(Integer, ForeignKey('user.id'))
	name = Column(String(50), nullable=False)
	budgets = relationship('Budget', cascade='all, delete-orphan')

class Budget(Base):
	__tablename__ = 'budget'
	id = Column(Integer, primary_key=True)
	period_id = Column(Integer, ForeignKey('period.id'))
	name = Column(String(100), nullable=False)
	budget_amount = Column(Integer)
	actual_amount = Column(Integer)

	@property
	def serialize(self):
		# returns object data in easily serializable format
		return {
			'item_name': self.name,
			'budget_amount': self.budget_amount,
			'actual_amount': self.actual_amount,
		}

# CONFIGURATION # # # # # # # # # # # # # # # # # # # # # # # # # #
# To establish lazy connection to the database:
engine = create_engine('postgresql://catalog:catalog@localhost/personalbudget')
# To create tables in the database if they don't exist yet:
Base.metadata.create_all(engine)
