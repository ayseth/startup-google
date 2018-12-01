from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from startup_setup import Startup, Base, Founder

engine = create_engine('sqlite:///startup.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# startups
startup1 = Startup(name="Machina")

session.add(startup1)
session.commit()

founder1_1 = Founder(name="Misha", bio="Computer Scientest, Full Stack Developer, IOS Developer.",
                      startup=startup1)

session.add(founder1_1)
session.commit()


founder2_1 = Founder(name="Cameron", bio="Computer Scientest, Full Stack Developer, Data Scientest.",
                      startup=startup1)

session.add(founder2_1)
session.commit()





startup2 = Startup(name="Sera")

session.add(startup2)
session.commit()

founder1_2 = Founder(name="Shanon", bio="Computer  Engineer, Linux Developer.",
                      startup=startup2)

session.add(founder1_2)
session.commit()




startup3 = Startup(name="Hush")

session.add(startup3)
session.commit()

founder1_3 = Founder(name="Alex", bio="Mobile Developer, Game Developer.",
                      startup=startup3)

session.add(founder1_3)
session.commit()


founder2_3 = Founder(name="william", bio="Computer Scientest, Full Stack Developer, Data Scientest.",
                      startup=startup3)

session.add(founder2_3)
session.commit()




startup4 = Startup(name="Full Contact")

session.add(startup4)
session.commit()

founder1_4 = Founder(name="Travis", bio="Computer Engineer, Business expert.",
                      startup=startup4)

session.add(founder1_4)
session.commit()


founder2_4 = Founder(name="Dan", bio="Computer Scientest, Mobile Developer.",
                      startup=startup4)

session.add(founder2_4)
session.commit()



startup5 = Startup(name="OLX")

session.add(startup5)
session.commit()

founder1_5 = Founder(name="Benjamin", bio="Business Manager.",
                      startup=startup5)

session.add(founder1_5)
session.commit()


founder2_5 = Founder(name="Nitish", bio="Computer Scientest, Full Stack Developer, Data Scientest.",
                      startup=startup5)

session.add(founder2_5)
session.commit()
print "added startups!"
